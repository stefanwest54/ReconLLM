#!/usr/bin/env python3
"""
ReconLLM — LLM-assisted penetration testing automation

Usage:
    python3 recon.py <target> [options]

Examples:
    # Basic scan
    python3 recon.py 10.0.0.100

    # Custom nmap args
    python3 recon.py scanme.nmap.org --nmap-args="-sS -p 80,443,8080"

    # Automated mode (no prompts)
    python3 recon.py 192.168.1.50 --auto

    # Bug bounty engagement
    python3 recon.py target.com --type bugbounty

    # CTF
    python3 recon.py ctf.local --type ctf

Set the RECONLLM_INITIAL_MODEL, RECONLLM_FOLLOWUP_MODEL, RECONLLM_LOOT_MODEL,
and RECONLLM_SUMMARY_MODEL environment variables to override model selection.
"""

import argparse
import datetime
import re
import select
import sys
import termios
import threading
import tty

from analyst import LLMAnalyst, _build_system_prompt, get_model
from loot import Loot, load_loot, save_loot
from notes import autosave_session, read_notes, notes_path, remove_autosave, write_session
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


def c(color: str, text: str) -> str:
    """Colorize text."""
    return f"{color}{text}{RESET}"


def section(title: str) -> None:
    """Print a section header."""
    print(f"\n{BOLD}{BLUE}{_BAR_HEAVY}{RESET}")
    print(f"{BOLD}{BLUE}  {title}{RESET}")
    print(f"{BOLD}{BLUE}{_BAR_HEAVY}{RESET}\n")


def info(msg: str) -> None:
    """Print info message."""
    print(f"{CYAN}[*]{RESET} {msg}")


def good(msg: str) -> None:
    """Print success message."""
    print(f"{GREEN}[+]{RESET} {msg}")


def warn(msg: str) -> None:
    """Print warning message."""
    print(f"{YELLOW}[!]{RESET} {msg}")


def error(msg: str) -> None:
    """Print error message."""
    print(f"{RED}[ERROR]{RESET} {msg}")


def print_scan_result(result: ScanResult) -> None:
    """Print the results of a scan."""
    if result.success:
        good(f"{result.tool.upper()} complete (exit {result.returncode})")
    else:
        warn(f"{result.tool.upper()} exited with code {result.returncode}")
    if result.stdout:
        out = result.stdout.strip()

        is_html = out.startswith("<") or bool(re.search(r"<!DOCTYPE", out, re.IGNORECASE))
        display_limit = MAX_HTML_DISPLAY_CHARS if is_html else MAX_DISPLAY_CHARS

        if len(out) > display_limit:
            print(out[:display_limit])
            html_note = " — HTML response" if is_html else ""
            print(
                f"{YELLOW}... [{len(out) - display_limit} chars truncated{html_note}"
                f" — full output in session log]{RESET}"
            )
        else:
            print(out)
    if result.stderr:
        warn(f"stderr: {result.stderr.strip()}")


def print_manual_steps(steps: list[str]) -> None:
    """Print manual steps that require operator action."""
    if not steps:
        return
    print(f"\n{BOLD}{MAGENTA}{_BAR_LIGHT}{RESET}")
    print(f"{BOLD}{MAGENTA}  MANUAL STEPS{RESET}")
    print(f"{BOLD}{MAGENTA}{_BAR_LIGHT}{RESET}")
    for i, step in enumerate(steps, 1):
        print(f"  {BOLD}{MAGENTA}{i}.{RESET} {step}")
    print(f"{BOLD}{MAGENTA}{_BAR_LIGHT}{RESET}\n")


def print_loot(loot: Loot) -> None:
    """Print a summary of captured loot."""
    if loot.is_empty():
        return
    print(f"\n{BOLD}{YELLOW}{_BAR_LIGHT}{RESET}")
    print(f"{BOLD}{YELLOW}  LOOT{RESET}")
    print(f"{BOLD}{YELLOW}{_BAR_LIGHT}{RESET}")
    print(loot.summary())
    print(f"{BOLD}{YELLOW}{_BAR_LIGHT}{RESET}\n")


_session_log: list[str] = []
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

_LOOT_SKIP_TOOLS = frozenset({"searchsploit", "sshpass"})
_AUTH_FAILURE_CODES = frozenset({5})
_HTTP_SKIP_CODES = re.compile(r"^HTTP/\S+\s+[45]\d{2}", re.MULTILINE)
_HTTP_ERROR_BODY = re.compile(r"<title>\s*[45]\d{2}\b", re.IGNORECASE)

_INTERACTIVE_TOOLS = frozenset({
    "nc", "netcat", "ncat",
    "ssh", "sftp", "scp",
    "telnet", "ftp",
    "mysql", "psql", "sqlite3", "mongo",
    "python", "python3", "python2",
    "bash", "sh", "zsh", "fish",
    "irb", "node",
})


def _strip_shell_operators(cmd: str) -> str:
    """Strip shell operators from the end of a command (redirects, pipes, etc.)."""
    cmd = re.sub(r'\s+2?>(?:&1|/dev/null)\s*$', '', cmd).strip()
    for op in (' && ', ' || ', '; '):
        if op in cmd:
            cmd = cmd[:cmd.index(op)].strip()
    if ' | ' in cmd:
        cmd = cmd[:cmd.index(' | ')].strip()
    return cmd


def _tool_basename(cmd: str) -> str:
    """Extract the tool name from a command."""
    if not cmd:
        return ""
    return cmd.split()[0]


def _filter_interactive(cmds: list[str]) -> list[str]:
    """Remove commands that open interactive sessions from a suggestion list."""
    return [cmd for cmd in cmds if _tool_basename(cmd) not in _INTERACTIVE_TOOLS]


def log(text: str) -> None:
    """Log text to the session log (without ANSI codes)."""
    _session_log.append(_ANSI_ESCAPE.sub("", text))


def stream_and_collect(generator) -> str:
    """Stream output from a generator and collect it into a string."""
    full = ""
    for chunk in generator:
        print(chunk, end="", flush=True)
        full += chunk
    print()
    log(full)
    return full


def _collect_response(generator) -> str:
    """
    Buffer LLM tokens silently with a spinning indicator.

    Shows a braille spinner that rotates every 200 chars received.
    Returns the full response text (logged and saved).
    Clears the spinner line cleanly when done.
    """
    full = ""
    spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    spinner_idx = 0
    chars_since_spin = 0
    SPIN_EVERY = 200

    for chunk in generator:
        full += chunk
        chars_since_spin += len(chunk)
        if chars_since_spin >= SPIN_EVERY:
            print(
                f"\r{CYAN}[*]{RESET}  {spinner_chars[spinner_idx % len(spinner_chars)]} thinking …",
                end="",
                flush=True,
            )
            spinner_idx += 1
            chars_since_spin = 0

    print("\r\033[K", end="", flush=True)

    log(full)
    return full


def _render_markdown_inline(text: str) -> str:
    """
    Render markdown formatting as ANSI for inline display.

    Converts:
    - **bold** → ANSI bold
    - [Critical]/[High]/[Medium]/[Low]/[Info] → colorized
    - `code` → plain text
    - *italic*, _underscore_ → plain text
    """
    text = re.sub(r"\*\*(.+?)\*\*", BOLD + r"\1" + RESET, text)

    text = re.sub(r"\*(.+?)\*", r"\1", text)
    text = re.sub(r"_(.+?)_", r"\1", text)

    severity_colors = {
        "Critical": RED + BOLD,
        "High": RED,
        "Medium": YELLOW,
        "Low": GREEN,
        "Info": CYAN,
    }
    for tag, color in severity_colors.items():
        text = text.replace(f"[{tag}]", f"{color}[{tag}]{RESET}")

    text = re.sub(r"`([^`]+)`", r"\1", text)

    return text


def _print_analysis(text: str) -> None:
    """
    Parse and format the LLM analysis response.

    - Parses ## Section headings
    - Displays ## Phase: as ◆ Phase: <name>
    - Suppresses ## Commands and ## Manual Steps sections
    - Applies markdown rendering to content
    """
    heading_re = re.compile(r"^##\s+(.+)$", re.MULTILINE)
    matches = list(heading_re.finditer(text))

    sections = []
    for i, m in enumerate(matches):
        heading = m.group(1).strip()
        content_start = m.end()
        content_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        content = text[content_start:content_end].strip()
        sections.append((heading, content))

    preamble = ""
    if matches:
        preamble = text[: matches[0].start()].strip()

    SUPPRESS_PREFIXES = ("commands", "manual steps", "manual step")

    def _is_suppressed(heading: str) -> bool:
        lower = heading.lower()
        return any(lower.startswith(p) for p in SUPPRESS_PREFIXES)

    print(f"{MAGENTA}{BOLD}{_BAR_LIGHT}{RESET}")

    if preamble:
        print()
        print(_render_markdown_inline(preamble))
        print()

    for heading, content in sections:
        if _is_suppressed(heading):
            continue

        if heading.lower().startswith("phase:"):
            phase_value = heading[6:].strip()
            print(f"\n{BOLD}{CYAN}◆ Phase: {phase_value}{RESET}\n")
            continue

        display_heading = re.sub(r"\s*\(.*?\)\s*$", "", heading).strip()
        print(f"\n  {BOLD}{WHITE}{display_heading}{RESET}")
        print()

        for line in content.splitlines():
            stripped = line.strip()
            if not stripped:
                print()
                continue
            if re.match(r"^(CMD:|Reason:|MANUAL:)", stripped):
                continue
            if re.match(r"^\|", stripped):
                continue
            if re.match(r"^[-|: ]+$", stripped) and "|" in stripped:
                continue
            if re.match(r"^#+\s", stripped):
                continue
            print(f"    {_render_markdown_inline(stripped)}")
        print()

    print(f"{MAGENTA}{BOLD}{_BAR_LIGHT}{RESET}")


def _skip_watcher(stop_event: threading.Event, done_event: threading.Event) -> None:
    """
    Monitor stdin for 's' key press to skip the current command.

    Sets stop_event when 's' is pressed.
    Exits when done_event is set or on terminal I/O errors.
    """
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not done_event.is_set():
            r, _, _ = select.select([sys.stdin], [], [], 0.1)
            if r:
                try:
                    ch = sys.stdin.read(1)
                    if ch.lower() == "s":
                        stop_event.set()
                        return
                except (EOFError, ValueError):
                    return
    except (OSError, termios.error):
        pass
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except (OSError, termios.error):
            pass


def save_report(path: str, target: str, engagement_type: str) -> None:
    """Save the session log to a report file."""
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


def _analyst_response(
    generator,
    model_label: str,
    session_parts: list[str],
    log_prefix: str,
    target: str,
    analyst: LLMAnalyst,
) -> tuple[str, list[str]]:
    """
    Collect and format the analyst's response.

    - Buffers LLM tokens with a spinner
    - Formats the analysis output
    - Extracts and returns suggested commands
    - Prints manual steps (once)
    - Autosaves the session
    """
    print(f"{CYAN}[*]{RESET} Sending to {model_label} …  ", end="", flush=True)

    analysis = _collect_response(generator)

    info(f"Received response from {model_label}")

    _print_analysis(analysis)

    session_parts.append(f"{log_prefix}\n{analysis}")
    autosave_session(target, session_parts)

    suggested = _filter_interactive(analyst.extract_commands(analysis))
    print_manual_steps(analyst.extract_manual_steps(analysis))

    return analysis, suggested


def read_user_input() -> str:
    """
    Read multi-line user input from stdin.

    Reads lines until user types 'END' on a line by itself.
    """
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


def _run_loot_extraction(text: str, loot: Loot, analyst: LLMAnalyst, label: str = "") -> None:
    """Extract loot from text and merge into the loot object."""
    extracted = analyst.extract_loot_from_text(text, loot)
    new_items = loot.merge(extracted)
    if new_items:
        tag = f" ({label})" if label else ""
        good(f"Loot: {new_items} new item(s) captured{tag}")
        loot.save()
        high_value = (
            extracted.get("credentials") or
            extracted.get("hashes") or
            extracted.get("tokens") or
            extracted.get("shell_access")
        )
        if high_value:
            print_loot(loot)


def prompt_action(cmds: list[str], auto: bool) -> tuple[str, list[str]]:
    """
    Prompt the user for the next action.

    Options: yes (run all), select (pick some), input (paste), attack (plan), quit
    """
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
    options.append(f"[{BOLD}a{RESET}{YELLOW}]ttack plan")
    options.append(f"[{BOLD}q{RESET}{YELLOW}]uit")

    print(f"\n{YELLOW}What next? {' / '.join(options)}: {RESET}", end="")
    choice = input().strip().lower()

    if choice in ("q", "quit", "n", "no", "exit"):
        return "quit", []

    if choice in ("i", "input"):
        return "input", []

    if choice in ("a", "attack", "plan", "attack plan"):
        return "attack", []

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


def _run_resume(
    prior_notes: str, target: str, analyst: LLMAnalyst,
    session_parts: list[str]
) -> tuple[str, list[str]]:
    """Resume an engagement from prior notes."""
    section("RESUMING ENGAGEMENT")
    analysis, suggested = _analyst_response(
        analyst._stream(f"Resume from prior notes:\n\n{prior_notes}"),
        model_label=analyst.model,
        session_parts=session_parts,
        log_prefix="[RESUMED FROM NOTES]\n\n[ANALYST BRIEFING]",
        target=target,
        analyst=analyst,
    )
    return analysis, suggested


def _run_scan(
    args, target: str, analyst: LLMAnalyst, prior_notes: str,
    session_parts: list[str]
) -> tuple[str, list[str]]:
    """Run the initial reconnaissance scan."""
    initial_model = analyst.model
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
    prompt = (
        "Analyze the following scan results. Identify open ports, services, and potential vulnerabilities. "
        "Suggest the next steps (commands, manual testing, etc.).\n\n"
        f"{combined}"
    )
    if prior_notes:
        prompt = f"Prior notes:\n{prior_notes}\n\nNew scan:\n{combined}"

    analysis, suggested = _analyst_response(
        analyst._stream(prompt),
        model_label=initial_model,
        session_parts=session_parts,
        log_prefix="[INITIAL ANALYSIS]",
        target=target,
        analyst=analyst,
    )

    return analysis, suggested


def _interactive_loop(
    args, target: str, analyst: LLMAnalyst, loot: Loot,
    session_parts: list[str], initial_suggested: list[str]
) -> tuple[bool, int]:
    """Main interactive engagement loop."""
    round_num = 0
    user_quit = False
    suggested = initial_suggested

    for round_num in range(1, args.max_rounds + 1):
        action, to_run = prompt_action(suggested, args.auto)

        if action == "quit":
            user_quit = True
            info("Exiting.")
            break

        if action == "input":
            user_input = read_user_input()
            if not user_input.strip():
                warn("No input provided. Try again.")
                continue

            _run_loot_extraction(user_input, loot, analyst, label="user input")

            section(f"ROUND {round_num} — INPUT")
            prompt = f"Analyze the following user input and suggest next steps:\n\n{user_input}"
            analysis, suggested = _analyst_response(
                analyst._stream(prompt),
                model_label=get_model('followup'),
                session_parts=session_parts,
                log_prefix=f"[ROUND {round_num} — USER INPUT]\n{user_input}\n\n[ANALYSIS]",
                target=target,
                analyst=analyst,
            )
            continue

        if action == "attack":
            section(f"ROUND {round_num} — ATTACK PLAN")
            print(f"{YELLOW}Ask the analyst anything — paste curl output, shell results, or any question.")
            print(f"Type {BOLD}back{RESET}{YELLOW} on its own line to return, or {BOLD}END{RESET}{YELLOW} to submit multi-line input.{RESET}\n")
            while True:
                user_input = read_user_input()
                stripped = user_input.strip()
                if not stripped or stripped.lower() in ("back", "done", "exit", "q"):
                    break
                print(f"\n{MAGENTA}{BOLD}{_BAR_LIGHT}{RESET}")
                prompt = f"Based on the engagement so far, create an attack plan:\n\n{user_input}"
                plan = stream_and_collect(analyst._stream(prompt))
                print(f"{MAGENTA}{BOLD}{_BAR_LIGHT}{RESET}\n")
                session_parts.append(
                    f"[ATTACK PLAN — ROUND {round_num}]\nQ: {user_input}\n\n{plan}"
                )
                autosave_session(target, session_parts)
            continue

        if not to_run:
            info("No commands selected.")
            break

        section(f"ROUND {round_num} — EXECUTION")
        followup_parts: list[str] = []
        round_note_lines = [f"[ROUND {round_num}]", "Commands run:"]

        for cmd in to_run:
            cmd = _strip_shell_operators(cmd)
            tool_name = _tool_basename(cmd)
            if not tool_name:
                continue
            if tool_name in _INTERACTIVE_TOOLS:
                warn(f"Skipping interactive command (use Ctrl+C if one hangs): {cmd}")
                log(f"[SKIPPED - INTERACTIVE] {cmd}")
                round_note_lines.append(f"  {cmd} (skipped — interactive)")
                continue

            info(f"Running: {c(BOLD, cmd)}  {YELLOW}[s = skip]{RESET}")
            stop_event = threading.Event()
            done_event = threading.Event()
            watcher = threading.Thread(
                target=_skip_watcher, args=(stop_event, done_event), daemon=True
            )
            try:
                watcher.start()
            except Exception as e:
                warn(f"Failed to start skip watcher: {type(e).__name__}: {e}")
                result = run_command(cmd, stop_event=None)
            else:
                result = run_command(cmd, stop_event=stop_event)
                done_event.set()
                join_timeout = 65
                watcher.join(timeout=join_timeout)
                if watcher.is_alive():
                    warn(
                        f"Skip watcher thread did not exit cleanly (timeout={join_timeout}s). "
                        f"This may indicate a terminal I/O issue."
                    )

            if result.returncode == -1:
                warn(f"Skipped: {cmd}")
                log(f"[SKIPPED] {cmd}")
                round_note_lines.append(f"  {cmd} (skipped)")
                analyst.seen_commands.add(cmd)
                continue

            print_scan_result(result)
            full_report = result.to_report()
            log(full_report)
            llm_report = full_report if len(full_report) <= MAX_RESULT_CHARS else (
                full_report[:MAX_RESULT_CHARS]
                + f"\n...[truncated — {len(full_report) - MAX_RESULT_CHARS} chars not shown]"
            )
            followup_parts.append(llm_report)
            round_note_lines.append(f"  {cmd}")

            curl_4xx = (
                result.tool == "curl"
                and (
                    bool(_HTTP_SKIP_CODES.search(result.stdout))
                    or bool(_HTTP_ERROR_BODY.search(result.stdout))
                )
            )
            if (result.returncode not in (127, *_AUTH_FAILURE_CODES)
                    and result.tool not in _LOOT_SKIP_TOOLS
                    and not curl_4xx):
                _run_loot_extraction(result.to_report(), loot, analyst, label=result.tool)

        round_note_lines.append("\nResults:\n" + "\n\n".join(followup_parts))

        section(f"ROUND {round_num} — ANALYSIS")
        prompt = f"Analyze the following command results and suggest next steps:\n\n{chr(10).join(followup_parts)}"
        analysis, suggested = _analyst_response(
            analyst._stream(prompt),
            model_label=get_model('followup'),
            session_parts=session_parts,
            log_prefix=f"\n".join(round_note_lines),
            target=target,
            analyst=analyst,
        )

        if not suggested:
            good("No further commands suggested.")
            action, _ = prompt_action([], args.auto)
            if action == "input":
                user_input = read_user_input()
                if user_input.strip():
                    _run_loot_extraction(user_input, loot, analyst, label="user input")
                    display_round = round_num + 1
                    section(f"ROUND {display_round} — INPUT")
                    prompt = f"Analyze the following user input and suggest next steps:\n\n{user_input}"
                    analysis, suggested = _analyst_response(
                        analyst._stream(prompt),
                        model_label=get_model('followup'),
                        session_parts=session_parts,
                        log_prefix=f"[ROUND {display_round} — USER INPUT]\n{user_input}\n\n[ANALYSIS]",
                        target=target,
                        analyst=analyst,
                    )
                    continue
            break
    else:
        warn(f"Reached maximum of {args.max_rounds} rounds.")

    return user_quit, round_num


def _finalize(
    args, target: str, analyst: LLMAnalyst, loot: Loot,
    session_parts: list[str], round_num: int, user_quit: bool
) -> None:
    """Finalize the engagement and save reports."""
    if not user_quit:
        section("ATTACK VECTOR SUMMARY")
        info(f"Asking {get_model('summary')} to summarize attack vectors …\n")
        print(f"{MAGENTA}{BOLD}{_BAR_LIGHT}{RESET}")
        try:
            prompt = "Summarize the key attack vectors and findings from this engagement."
            summary = stream_and_collect(analyst._stream(prompt))
        except KeyboardInterrupt:
            warn("Summary interrupted.")
            summary = ""
        except RuntimeError as e:
            warn(f"Summary skipped: {e}")
            summary = ""
        print(f"{MAGENTA}{BOLD}{_BAR_LIGHT}{RESET}")
        if summary:
            session_parts.append(f"[ATTACK VECTOR SUMMARY]\n{summary}")

    loot.seen_commands = sorted(analyst.seen_commands)
    if not loot.is_empty():
        session_parts.append(f"[LOOT]\n{loot.summary()}")
    loot.save()

    notes_file = write_session(
        target,
        "\n\n".join(session_parts),
        args.engagement_type,
    )
    remove_autosave(target)

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


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
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
        "--model", default="",
        help="Override the initial analysis model (e.g. groq/llama-3.3-70b-versatile). "
             "Defaults to RECONLLM_INITIAL_MODEL env var or claude-haiku-4-5-20251001.",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=30,
        help="Maximum follow-up rounds (default: 30)",
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
    """Main entry point."""
    print(BANNER)
    args = parse_args()

    target = args.target
    initial_model = args.model or get_model("initial")
    info(f"Target  : {c(CYAN, target)}")
    info(f"Model   : {c(CYAN, initial_model)}")
    info(f"Type    : {c(CYAN, args.engagement_type)}")
    info(f"Nmap    : {c(CYAN, args.nmap_args)}")

    prior_notes = read_notes(target)
    loot = load_loot(target)
    system_prompt = _build_system_prompt(args.engagement_type)
    analyst = LLMAnalyst(model=initial_model, system_prompt=system_prompt)
    session_parts: list[str] = []

    analyst.seen_commands = set(loot.seen_commands)

    if not loot.is_empty():
        good(f"Prior loot loaded for {target}")
        print_loot(loot)

    resuming = False
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

    if not resuming and not loot.is_empty():
        print(f"\n{YELLOW}Prior loot exists for {target}. Keep it or clear it for this session?")
        print(f"  [{BOLD}k{RESET}{YELLOW}]eep  — carry loot forward into this session")
        print(f"  [{BOLD}c{RESET}{YELLOW}]lear — discard loot and start clean")
        print(f"\nChoice: {RESET}", end="")
        if input().strip().lower() in ("c", "clear"):
            loot = Loot(target=target)
            loot.save()
            good("Loot cleared.")

    if resuming:
        analysis, suggested = _run_resume(prior_notes, target, analyst, session_parts)
    else:
        analysis, suggested = _run_scan(args, target, analyst, prior_notes, session_parts)

    user_quit, round_num = _interactive_loop(args, target, analyst, loot, session_parts, suggested)

    _finalize(args, target, analyst, loot, session_parts, round_num, user_quit)


if __name__ == "__main__":
    _target = None
    try:
        _target = next((a for a in sys.argv[1:] if not a.startswith("-")), None)
        main()
    finally:
        if _target:
            remove_autosave(_target)
