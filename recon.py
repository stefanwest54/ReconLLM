#!/usr/bin/env python3
""" recon.py - LLM-assisted automated reconnaissance and exploitation framework.

Usage:
    python recon.py <target> [options]

Examples:
    python recon.py 192.168.1.1
    python recon.py scanme.nmap.org --nmap-args "-sV -T4 -p-"
    python recon.py 10.10.10.0/24 --no-ping
    python recon.py 10.10.10.5 --type bugbounty --output report.txt
    python recon.py 10.10.10.5 --type ctf --auto  """

import argparse
import datetime
import os
import re
import select
import sys
import termios
import threading
import tty

from analyst import PenTestAnalyst, extract_loot_from_text
from loot import Loot, load_loot, save_loot
from notes import load_notes, notes_path, sanitize, write_session
from scanner import ScanResult, nmap_scan, ping_host, run_command

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[37m"


_BAR_WIDTH = 62
_BAR_HEAVY = "=" * _BAR_WIDTH
_BAR_LIGHT = "─" * _BAR_WIDTH

MAX_DISPLAY_CHARS = 3000
MAX_HTML_DISPLAY_CHARS = 500
MAX_RESULT_CHARS = 2000

BANNER = f"""{RED}{BOLD}
  ███████╗███╗   ██╗████████╗██████╗  ██████╗ ██████╗ ██╗   ██╗
  ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔═══██╗██╔══██╗╚██╗ ██╔╝
  █████╗  ██╔██╗ ██║   ██║   ██████╔╝██║   ██║██████╔╝ ╚████╔╝
  ██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗██║   ██║██╔═══╝   ╚██╔╝
  ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝██║        ██║
  ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝        ╚═╝
{RESET}{WHITE}{BOLD}  LLM-Assisted Automated Reconnaissance Framework{RESET}
{WHITE}  [ ENTROPY v1.0 | Exploiting Network Targets, Recon, Ops, Payloads, Yanking ]{RESET}
{WHITE}  Authorized use only — ensure written permission before scanning{RESET}
"""

def print_scan_result(result: ScanResult) -> None:
    if result.success:
        good(f"{result.tool.upper()} complete (exit {result.returncode})")
    else:
        warn(f"{result.tool.upper()} exited with code {result.returncode}")
    if result.stdout:
        print(result.stdout.strip())
    if result.stderr:
        warn(f"stderr: {result.stderr.strip()}")


def print_loot(loot: Loot) -> None:
    if loot.is_empty():
        return
    bar = "─" * 62
    print(f"\n{BOLD}{YELLOW}{bar}{RESET}")
    print(f"{BOLD}{YELLOW}  LOOT{RESET}")
    print(f"{BOLD}{YELLOW}{bar}{RESET}")
    print(loot.summary())
    print(f"{BOLD}{YELLOW}{bar}{RESET}\n")


_session_log: list[str] = []


def log(text: str) -> None:
    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    _session_log.append(ansi_escape.sub("", text))


def stream_and_collect(generator) -> str:
    full = ""
    for chunk in generator:
        print(chunk, end="", flush=True)
        full += chunk
    print()
    log(full)
    return full


def _skip_watcher(stop_event: threading.Event, done_event: threading.Event) -> None:
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not done_event.is_set():
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if r:
                ch = sys.stdin.read(1)
                if ch.lower() == "s":
                    stop_event.set()
                    return
    except Exception:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def save_report(path: str, target: str, engagement_type: str) -> None:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = (
        f"ReconLLM Report\n"
        f"Generated : {timestamp}\n"
        f"Target    : {target}\n"
        f"Type      : {engagement_type}\n"
        f"{'='*62}\n\n"
    )
    with open(path, "w") as fh:
        fh.write(header)
        fh.write("\n".join(_session_log))
    good(f"Report saved → {path}")


def read_user_input() -> str:
    print(f"\n{YELLOW}Enter your input below (question, pasted output, web content, etc.).")
    print(f"Type {BOLD}END{RESET}{YELLOW} on a new line when finished:{RESET}\n")

    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip().upper() == "END":
            break
        lines.append(line)

    return "\n".join(lines)


def _run_loot_extraction(
    client, model: str, text: str, loot: Loot, label: str = ""
) -> None:
    extracted = extract_loot_from_text(client, model, text)
    new_items = loot.merge(extracted)
    if new_items:
        tag = f" ({label})" if label else ""
        good(f"Loot: {new_items} new item(s) captured{tag}")
        save_loot(loot)
        high_value = (
            extracted.get("credentials") or
            extracted.get("hashes") or
            extracted.get("tokens") or
            extracted.get("shell_access")
        )
        if high_value:
            print_loot(loot)


def prompt_action(cmds: list[str], auto: bool) -> tuple[str, list[str]]:
    if cmds:
        print(f"\n{GREEN}{BOLD}Suggested commands:{RESET}")
        for i, cmd in enumerate(cmds, 1):
            print(f"  {BOLD}{i}.{RESET} {cmd}")

    if auto and cmds:
        good("--auto mode: running all suggested commands.")
        return "run", cmds

    options = []
    if cmds:
        options.append(f"[{BOLD}y{RESET}{YELLOW}]es")
        options.append(f"[{BOLD}s{RESET}{YELLOW}]elect")
    options.append(f"[{BOLD}i{RESET}{YELLOW}]nput")
    options.append(f"[{BOLD}q{RESET}{YELLOW}]uit")

    print(f"\n{YELLOW}What next? {' / '.join(options)}: {RESET}", end="")
    choice = input().strip().lower()

    if choice in ("q", "quit", "n", "no", "exit"):
        return "quit", []

    if choice in ("i", "input"):
        return "input", []

    if choice in ("s", "select") and cmds:
        print("Enter numbers to run (comma-separated, e.g. 1,3): ", end="")
        raw = input().strip()
        selected = []
        for token in raw.split(","):
            try:
                idx = int(token.strip()) - 1
                if 0 <= idx < len(cmds):
                    selected.append(cmds[idx])
            except ValueError:
                pass
        return "run", selected

    return "run", cmds

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="LLM-assisted automated reconnaissance and exploitation tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="Target IP, hostname, or CIDR range")
    parser.add_argument(
        "--nmap-args",
        default="-sV -T4 --top-ports 1000",
        metavar="ARGS",
        help='nmap argument string (default: "-sV -T4 --top-ports 1000")',
    )
    parser.add_argument(
        "--no-ping", action="store_true",
        help="Skip the initial ping check",
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Automatically run all suggested commands without prompting",
    )
    parser.add_argument(
        "--model", default="claude-opus-4-6",
        help="Claude model ID (default: claude-opus-4-6)",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=10,
        help="Maximum follow-up rounds (default: 10)",
    )
    parser.add_argument(
        "--type", dest="engagement_type",
        choices=["pentest", "bugbounty", "ctf"],
        default="pentest",
        help="Engagement type: pentest | bugbounty | ctf (default: pentest)",
    )
    parser.add_argument(
        "--output", metavar="FILE",
        help="Save full session report to FILE (plain text)",
    )
    return parser.parse_args()

def main() -> None:
    print(BANNER)
    args = parse_args()

    if not os.environ.get("ANTHROPIC_API_KEY"):
        error("ANTHROPIC_API_KEY is not set.")
        print("  Export it first:  export ANTHROPIC_API_KEY='sk-ant-...'")
        sys.exit(1)

    target = args.target
    info(f"Target  : {c(CYAN, target)}")
    info(f"Model   : {c(CYAN, args.model)}")
    info(f"Type    : {c(CYAN, args.engagement_type)}")
    info(f"Nmap    : {c(CYAN, args.nmap_args)}")

    prior_notes = load_notes(target)
    loot = load_loot(target)
    analyst = PenTestAnalyst(model=args.model, engagement_type=args.engagement_type)
    session_parts: list[str] = []

    if not loot.is_empty():
        good(f"Prior loot loaded for {target}")
        print_loot(loot)

    if prior_notes:
        npath = notes_path(target)
        good(f"Prior notes found: {npath}")
        print(f"\n{YELLOW}Resume from notes or run a fresh scan?")
        print(f"  [{BOLD}r{RESET}{YELLOW}]esume — load prior notes and continue from where you left off")
        print(f"  [{BOLD}s{RESET}{YELLOW}]can   — run a full scan against the target again")
        print(f"\nChoice: {RESET}", end="")
        resuming = input().strip().lower() in ("r", "resume")
    else:
        info(f"No prior notes for {target} — starting fresh.\n")
        resuming = False

    if not resuming and not loot.is_empty():
        print(f"\n{YELLOW}Prior loot exists for {target}. Keep it or clear it for this session?")
        print(f"  [{BOLD}k{RESET}{YELLOW}]eep  — carry loot forward into this session")
        print(f"  [{BOLD}c{RESET}{YELLOW}]lear — discard loot and start clean")
        print(f"\nChoice: {RESET}", end="")
        if input().strip().lower() in ("c", "clear"):
            loot = Loot(target=target)
            save_loot(loot)
            good("Loot cleared.")

    if resuming:
        section("RESUMING ENGAGEMENT")
        info(f"Loading prior notes into {args.model} …\n")
        print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
        analysis = stream_and_collect(analyst.resume_from_notes(prior_notes))
        print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
        session_parts.append(f"[RESUMED FROM NOTES]\n\n[ANALYST BRIEFING]\n{analysis}")
        _run_loot_extraction(analyst.client, analyst.model, analysis, loot)

    else:
        scan_reports: list[str] = []

        if not args.no_ping:
            section("PHASE 1 — HOST DISCOVERY (PING)")
            info(f"Pinging {target} ...")
            ping_result = ping_host(target)
            print_scan_result(ping_result)
            log(ping_result.to_report())
            scan_reports.append(ping_result.to_report())
            if not ping_result.success:
                warn("Host may be down or blocking ICMP. Proceeding with nmap anyway.")

        section("PHASE 2 — PORT & SERVICE SCAN (NMAP)")
        info(f"Running: nmap {args.nmap_args} {target}")
        info("This may take a few minutes …")
        print()

        nmap_result = nmap_scan(target, args.nmap_args)
        print_scan_result(nmap_result)
        log(nmap_result.to_report())
        scan_reports.append(nmap_result.to_report())

        if not nmap_result.stdout and not nmap_result.success:
            error("nmap returned no output and a non-zero exit code. Aborting.")
            sys.exit(1)

        combined = "\n\n".join(scan_reports)
        session_parts.append(f"[SCAN RESULTS]\n{combined}")

        section("PHASE 3 — ANALYSIS")
        info(f"Sending scan results to {args.model} …\n")
        print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
        if prior_notes:
            analysis = stream_and_collect(
                analyst.analyze_initial_with_history(combined, prior_notes)
            )
        else:
            analysis = stream_and_collect(analyst.analyze_initial(combined))
        print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
        session_parts.append(f"[INITIAL ANALYSIS]\n{analysis}")
        _run_loot_extraction(analyst.client, analyst.model, analysis, loot)

    suggested = PenTestAnalyst.extract_commands(analysis)

    round_num = 0
    for round_num in range(1, args.max_rounds + 1):

        action, to_run = prompt_action(suggested, args.auto)

        if action == "quit":
            info("Exiting.")
            break

        if action == "input":
            user_input = read_user_input()
            if not user_input.strip():
                warn("No input provided. Try again.")
                round_num -= 1
                continue

            _run_loot_extraction(
                analyst.client, analyst.model,
                user_input, loot, label="user input"
            )

            section(f"ROUND {round_num} — INPUT")
            info(f"Sending to {args.model} …\n")
            print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
            analysis = stream_and_collect(analyst.analyze_freeform(user_input, loot))
            print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
            session_parts.append(
                f"[ROUND {round_num} — USER INPUT]\n{user_input}\n\n[ANALYSIS]\n{analysis}"
            )
            _run_loot_extraction(analyst.client, analyst.model, analysis, loot)
            suggested = PenTestAnalyst.extract_commands(analysis)
            continue

        if not to_run:
            info("No commands selected.")
            break

        section(f"ROUND {round_num} — EXECUTION")
        followup_parts: list[str] = []
        round_note_lines = [f"[ROUND {round_num}]", "Commands run:"]

        for cmd in to_run:
            info(f"Running: {c(BOLD, cmd)}  {YELLOW}[s = skip]{RESET}")
            stop_event = threading.Event()
            done_event = threading.Event()
            watcher = threading.Thread(
                target=_skip_watcher, args=(stop_event, done_event), daemon=True
            )
            watcher.start()
            result = run_command(cmd, stop_event=stop_event)
            done_event.set()
            watcher.join(timeout=1)

            if result.returncode == -1:
                warn(f"Skipped: {cmd}")
                log(f"[SKIPPED] {cmd}")
                round_note_lines.append(f"  {cmd} (skipped)")
                continue

            print_scan_result(result)
            log(result.to_report())
            followup_parts.append(result.to_report())
            round_note_lines.append(f"  {cmd}")

            _run_loot_extraction(
                analyst.client, analyst.model,
                result.to_report(), loot, label=result.tool
            )

        round_note_lines.append("\nResults:\n" + "\n\n".join(followup_parts))

        section(f"ROUND {round_num} — ANALYSIS")
        info(f"Sending results to {args.model} …\n")
        print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
        analysis = stream_and_collect(
            analyst.analyze_followup("\n\n".join(followup_parts), loot)
        )
        print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")

        _run_loot_extraction(analyst.client, analyst.model, analysis, loot)
        round_note_lines.append(f"\nAnalysis:\n{analysis}")
        session_parts.append("\n".join(round_note_lines))
        suggested = PenTestAnalyst.extract_commands(analysis)

        if not suggested:
            good("No further commands suggested.")
            action, _ = prompt_action([], args.auto)
            if action == "input":
                user_input = read_user_input()
                if user_input.strip():
                    _run_loot_extraction(
                        analyst.client, analyst.model,
                        user_input, loot, label="user input"
                    )
                    round_num += 1
                    section(f"ROUND {round_num} — INPUT")
                    info(f"Sending to {args.model} …\n")
                    print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
                    analysis = stream_and_collect(analyst.analyze_freeform(user_input, loot))
                    print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
                    session_parts.append(
                        f"[ROUND {round_num} — USER INPUT]\n{user_input}\n\n"
                        f"[ANALYSIS]\n{analysis}"
                    )
                    _run_loot_extraction(analyst.client, analyst.model, analysis, loot)
                    suggested = PenTestAnalyst.extract_commands(analysis)
                    continue
            break
    else:
        warn(f"Reached maximum of {args.max_rounds} rounds.")

    section("ATTACK VECTOR SUMMARY")
    info(f"Asking {args.model} to summarize attack vectors …\n")
    print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
    summary = stream_and_collect(analyst.generate_attack_summary())
    print(f"{MAGENTA}{BOLD}{'─'*62}{RESET}")
    session_parts.append(f"[ATTACK VECTOR SUMMARY]\n{summary}")

    if not loot.is_empty():
        session_parts.append(f"[LOOT]\n{loot.summary()}")
        save_loot(loot)

    notes_file = write_session(
        target,
        "\n\n".join(session_parts),
        args.engagement_type,
    )

    section("COMPLETE")
    good(f"Target : {target}")
    good(f"Type   : {args.engagement_type}")
    good(f"Rounds : {round_num}")
    good(f"Notes  : {notes_file}")

    if not loot.is_empty():
        print_loot(loot)

    if args.output:
        save_report(args.output, target, args.engagement_type)

    print(f"\n{BOLD}Authorized use only.{RESET}\n")


if __name__ == "__main__":
    main()
