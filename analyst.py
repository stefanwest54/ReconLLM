""" analyst.py - LLM-powered penetration test analyst using the Claude API with streaming. """

import contextlib
import json
import os
import re
import time
import urllib.parse
from typing import TYPE_CHECKING, Generator

from scanner import strip_shell_operators

os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")

import litellm

litellm.suppress_debug_info = True

try:
    from litellm.exceptions import MidStreamFallbackError as _MidStreamFallbackError
except ImportError:
    _MidStreamFallbackError = type("_NeverRaised", (Exception,), {})

if TYPE_CHECKING:
    from loot import Loot


MAX_HISTORY_TURNS = 4
MAX_LLM_INPUT_CHARS = 15000
_MAX_LOOT_CONTEXT_CHARS = 1500


def get_model(task: str) -> str:
    models = {
        "loot":     os.environ.get("RECONLLM_LOOT_MODEL",     "claude-haiku-4-5-20251001"),
        "followup": os.environ.get("RECONLLM_FOLLOWUP_MODEL", "claude-haiku-4-5-20251001"),
        "initial":  os.environ.get("RECONLLM_INITIAL_MODEL",  "claude-haiku-4-5-20251001"),
        "summary":  os.environ.get("RECONLLM_SUMMARY_MODEL",  "claude-haiku-4-5-20251001"),
    }
    return models.get(task, "claude-haiku-4-5-20251001")


_BASE_SYSTEM_PROMPT = (
    "You are an expert penetration tester. Analyze findings and suggest next steps.\n\n"
    "Output format (REQUIRED):\n"
    "# Analysis: [Target]\n\n"
    "## Findings\n[1-2 sentences: what services are running, what looks exploitable]\n\n"
    "## Next Steps\n[3-5 commands with CMD: prefix — only target-specific reconnaissance]\n\n"
    "LOOT EXTRACTION (ONLY actual secrets/API keys/real credentials/password hashes/files; skip if none):\n"
    "```json\n{\"credentials\": [], \"hashes\": [], \"tokens\": [], \"shell_access\": [], \"files\": []}\n```\n\n"
    "RULES:\n"
    "- NO boilerplate, templates, or generic examples\n"
    "- NO empty code blocks, risk summaries, or narrative fluff\n"
    "- NO local-only commands (sudo, cat, find, uname, etc.)\n"
    "- NO duplicate tools (nmap/ping already ran)\n"
    "- NO slow/long-running tools (nikto, nessus, openvas, wpscan, nuclei)\n"
    "- ABSOLUTELY NO analysis notes or commentary as 'loot'\n"
    "- ONLY extract: working credentials, password hashes, API tokens, shell access, or interesting files\n"
    "- HTTP responses, API endpoints, and analysis are NEVER loot\n"
    "- If nothing found to extract: skip the JSON block entirely\n"
    "- Findings section: max 50 words\n"
    "- Total output: max 300 words\n"
)


def _build_system_prompt(engagement_type: str = "pentest") -> str:
    addendum = {
        "bugbounty": (
            "\n\nEngagement context: Bug bounty program. "
            "Focus on OWASP Top 10, API security (OWASP API Top 10), subdomain enumeration, "
            "and web application logic flaws. Prioritize impact and reproducibility. "
            "Flag any finding that would typically qualify as P1/P2 on HackerOne or Bugcrowd."
        ),
        "ctf": (
            "\n\nEngagement context: Capture The Flag (CTF). "
            "Think creatively — unusual service configurations, steganography hints, "
            "non-standard ports, custom protocols, and intentionally vulnerable software "
            "are all fair game. Flag obvious CTF patterns (e.g. flag{}, THM{}, HTB{})."
        ),
        "pentest": (
            "\n\nEngagement context: Professional penetration test (authorized). "
            "Cover the full kill chain: reconnaissance → initial access → privilege escalation "
            "→ lateral movement → data exfiltration paths. Note any findings relevant to "
            "an executive risk report."
        ),
    }
    return _BASE_SYSTEM_PROMPT + addendum.get(engagement_type, addendum["pentest"])


def _try_parse_json_response(raw: str) -> dict | None:
    attempts = [
        ("as-is", raw),
        ("remove-leading-fence", re.sub(r"^```(?:json|python)?\n?", "", raw.strip())),
        ("remove-trailing-fence", re.sub(r"\n?```$", "", raw.strip())),
        ("remove-both-fences", re.sub(r"```(?:json|python)?\n?(.*?)\n?```", r"\1", raw, flags=re.DOTALL)),
        ("extract-json-block", _extract_first_json_block(raw)),
    ]

    for strategy_name, attempt in attempts:
        if not attempt:
            continue
        try:
            result = json.loads(attempt)
            if isinstance(result, dict):
                return result
        except (json.JSONDecodeError, ValueError):
            continue

    return None


def _extract_first_json_block(text: str) -> str:
    depth = 0
    in_string = False
    escape_next = False
    start = -1

    for i, char in enumerate(text):
        if escape_next:
            escape_next = False
            continue

        if char == "\\":
            escape_next = True
            continue

        if char == '"' and not escape_next:
            in_string = not in_string
            continue

        if in_string:
            continue

        if char == "{":
            if depth == 0:
                start = i
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0 and start != -1:
                return text[start:i+1]

    return ""


class LLMAnalyst:

    def __init__(self, model: str, system_prompt: str):
        self.model = model
        self.system_prompt = system_prompt
        self.messages: list[dict] = []
        self.seen_commands: set[str] = set()
        self.skipped_commands: set[str] = set()
        self.discovered_domains: set[str] = set()

    def extract_loot_from_text(self, text: str, loot: "Loot") -> dict:
        if not text or len(text) < 20:
            return {}

        loot_context = ""
        if loot.credentials:
            loot_context += f"Existing credentials: {len(loot.credentials)}\n"
        if loot.hashes:
            loot_context += f"Existing hashes: {len(loot.hashes)}\n"
        if loot.shell_access:
            loot_context += f"Existing shell access: {len(loot.shell_access)}\n"

        prompt = (
            "Extract all credentials, hashes, tokens, shell access, and interesting files "
            "from the following text. Return ONLY valid JSON (no markdown, no explanation).\n\n"
            f"{loot_context}\n"
            "Required JSON structure:\n"
            "{\n"
            '  "credentials": [{"username": "", "password": "", "service": "", "notes": ""}],\n'
            '  "hashes": [{"username": "", "hash_value": "", "hash_type": "", "cracked": "", "notes": ""}],\n'
            '  "tokens": [{"token_type": "", "value": "", "service": "", "notes": ""}],\n'
            '  "shell_access": [{"method": "", "user": "", "host": "", "notes": ""}],\n'
            '  "files": [{"path": "", "description": "", "notes": ""}],\n'
            '  "notes": [""]\n'
            "}\n\n"
            f"TEXT:\n{text[:_MAX_LOOT_CONTEXT_CHARS]}"
        )

        try:
            response = litellm.completion(
                model=get_model("loot"),
                max_tokens=1024,
                timeout=30,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.choices[0].message.content.strip()
            parsed = _try_parse_json_response(raw)
            return parsed if parsed else {}
        except (litellm.RateLimitError, litellm.AuthenticationError, litellm.BadRequestError) as e:
            import sys
            print(f"\n[!] Loot extraction {type(e).__name__}: {e}", file=sys.stderr)
            return {}
        except (litellm.Timeout, TimeoutError) as e:
            import sys
            print(f"\n[!] Loot extraction timed out: {type(e).__name__}", file=sys.stderr)
            return {}
        except Exception as e:
            import sys
            print(f"\n[!] Loot extraction failed: {type(e).__name__}: {e}", file=sys.stderr)
            return {}

    def _compress_history(self) -> None:
        if len(self.messages) <= MAX_HISTORY_TURNS * 2:
            return

        first_2 = self.messages[:2]
        last_4 = self.messages[-4:]
        middle = self.messages[2:-4]

        middle_text = "\n\n".join(
            f"[{m['role'].upper()}]: {m['content'] if isinstance(m['content'], str) else str(m['content'])}"
            for m in middle
        )

        try:
            response = litellm.completion(
                model=get_model("summary"),
                max_tokens=512,
                timeout=30,
                messages=[
                    {
                        "role": "user",
                        "content": (
                            "Summarize the following penetration test conversation turns into a "
                            "concise factual briefing. Include: confirmed findings, commands run, "
                            "results, and current engagement phase. Be terse — this replaces the "
                            "full history in context.\n\n" + middle_text
                        ),
                    }
                ],
            )
            summary = response.choices[0].message.content.strip()
        except (litellm.RateLimitError, litellm.AuthenticationError, litellm.BadRequestError) as e:
            import sys
            print(f"\n[!] History compression failed: {type(e).__name__}: {e}", file=sys.stderr)
            summary = "[Prior session history compressed — summary unavailable]"
        except (litellm.Timeout, TimeoutError) as e:
            import sys
            print(f"\n[!] History compression timed out: {type(e).__name__}", file=sys.stderr)
            summary = "[Prior session history compressed — summary unavailable]"
        except Exception as e:
            import sys
            print(f"\n[!] History compression failed: {type(e).__name__}: {e}", file=sys.stderr)
            summary = "[Prior session history compressed — summary unavailable]"

        summary_msg = {"role": "user", "content": f"[Prior session summary]:\n{summary}"}
        self.messages = first_2 + [summary_msg] + last_4

    def _stream(self, user_content: str) -> Generator[str, None, None]:
        if len(user_content) > MAX_LLM_INPUT_CHARS:
            user_content = (
                user_content[:MAX_LLM_INPUT_CHARS]
                + "\n\n[...input truncated to fit context window...]"
            )

        self.messages.append({"role": "user", "content": user_content})

        max_retries = 2
        for attempt in range(max_retries + 1):
            full_text = ""
            try:
                response = litellm.completion(
                    model=self.model,
                    max_tokens=8192,
                    timeout=120,
                    messages=[{"role": "system", "content": self.system_prompt}] + self.messages,
                    stream=True,
                )
                for chunk in response:
                    text = chunk.choices[0].delta.content or ""
                    if text:
                        full_text += text
                        yield text
                break
            except (litellm.RateLimitError, _MidStreamFallbackError) as e:
                if attempt == max_retries:
                    raise RuntimeError(
                        f"\n[!] Rate limit hit on '{self.model}' after {max_retries + 1} attempts.\n"
                        "    Set a different model via the relevant RECONLLM_*_MODEL env var."
                    ) from e
                delay = 15.0
                delay_match = re.search(r"retry in (\d+(?:\.\d+)?)", str(e), re.IGNORECASE)
                if delay_match:
                    delay = min(float(delay_match.group(1)) + 2, 60.0)
                print(f"\n[!] Rate limit on '{self.model}'. Retrying in {delay:.0f}s "
                      f"(attempt {attempt + 1}/{max_retries})...")
                time.sleep(delay)
            except (litellm.Timeout, TimeoutError) as e:
                if attempt == max_retries:
                    raise RuntimeError(
                        f"\n[!] LLM request timed out on '{self.model}' after {max_retries + 1} attempts.\n"
                        "    The API is too slow or unresponsive. Check your connection or switch models."
                    ) from e
                delay = min(10.0 * (attempt + 1), 30.0)
                print(f"\n[!] LLM request timed out. Retrying in {delay:.0f}s "
                      f"(attempt {attempt + 1}/{max_retries})...")
                time.sleep(delay)
            except litellm.AuthenticationError as e:
                raise RuntimeError(
                    f"\n[!] Authentication failed for '{self.model}'.\n"
                    "    Check the relevant API key environment variable."
                ) from e
            except litellm.BadRequestError as e:
                raise RuntimeError(
                    f"\n[!] Bad request to '{self.model}': {e}\n"
                    "    The input may be too long or contain unsupported content."
                ) from e

        self.messages.append({"role": "assistant", "content": full_text})
        self._compress_history()

    @contextlib.contextmanager
    def _use_model(self, task: str):
        old_model = self.model
        self.model = get_model(task)
        try:
            yield
        finally:
            self.model = old_model

    def _is_slow_nmap_command(self, cmd: str) -> bool:
        if not cmd.startswith("nmap"):
            return False
        if "--script=vuln" in cmd or "--script=http-enum" in cmd:
            if "-p" not in cmd:
                return True
        if " -p- " in cmd or " -p-" in cmd.split():
            if "--max-retries" not in cmd and "--host-timeout" not in cmd:
                return True
        if " -A " in cmd or cmd.endswith(" -A"):
            return True
        if " -O " in cmd and "-p" not in cmd:
            return True
        return False

    def _is_slow_tool(self, cmd: str) -> bool:
        slow_tools = ["nikto", "nessus", "openvas", "wpscan", "nuclei"]
        first_token = cmd.split()[0] if cmd.split() else ""
        return any(first_token.lower().endswith(tool) for tool in slow_tools)

    def _is_local_only_command(self, cmd: str) -> bool:
        local_only = [
            "sudo", "cat", "find", "grep", "ls", "pwd", "cd", "export",
            "echo", "uname", "id", "whoami", "which", "whereis", "file",
            "stat", "ps", "top", "htop", "netstat", "ss", "lsof",
            "iptables", "firewall", "selinux", "chmod", "chown", "chgrp",
            "cp", "mv", "rm", "touch", "mkdir", "rmdir", "tar", "zip",
            "unzip", "gzip", "gunzip", "sed", "awk", "cut", "head", "tail",
            "sort", "uniq", "wc", "diff", "patch", "make", "gcc", "python",
            "perl", "ruby", "node", "java", "gcc", "g++", "cc", "objdump",
            "strings", "readelf", "nm", "ldd", "strace", "ltrace", "gdb",
            "valgrind", "apt", "yum", "pip", "npm", "docker", "systemctl",
            "service", "journalctl", "dmesg", "syslog", "mount", "umount",
            "fdisk", "parted", "lsblk", "df", "du", "free", "ulimit",
        ]
        first_word = cmd.split()[0] if cmd.split() else ""
        return first_word in local_only

    def _is_already_run_command(self, cmd: str) -> bool:
        if cmd.startswith("nmap"):
            return True
        if cmd.startswith("ping"):
            return True
        return False

    def _is_valid_command(self, cmd: str) -> bool:
        if not cmd or len(cmd) < 3:
            return False

        if cmd.lower().startswith(("the ", "a ", "this ", "that ", "use ", "run ", "check ", "look for ")):
            return False

        if cmd.rstrip().endswith(('.', '?', '!')) and not cmd.rstrip().endswith(('.txt', '.json', '.py')):
            return False

        if '. ' in cmd or '? ' in cmd:
            return False

        if cmd.startswith(('#', '*', '-', '[', '(')) and not cmd.startswith(('# ', '[cmd')):
            return False

        if any(cmd.lower().startswith(p) for p in [
            "note", "remember", "important", "for example", "such as",
            "instead", "also", "furthermore", "however", "therefore"
        ]):
            return False

        if re.search(r'\$\{[^}]+\}|\$\([^)]+\)|\$[A-Za-z_][A-Za-z0-9_]*', cmd):
            return False

        if ' -' not in cmd and ' /' not in cmd and cmd.count(' ') < 1:
            if any(cmd.startswith(t) for t in ['curl', 'wget', 'git', 'ssh', 'nmap', 'nc']):
                return True
            return False

        return True

    def extract_commands(self, text: str) -> list[str]:
        manual_match = re.search(r"^##\s+Manual\s+Steps", text, re.MULTILINE | re.IGNORECASE)
        searchable = text[:manual_match.start()] if manual_match else text

        commands = []

        for line in searchable.splitlines():
            match = re.match(r"^\s*CMD:\s+(.+)", line)
            if match:
                cmd = match.group(1).strip().strip("`")
            else:
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "-", "|", "=")) or len(stripped) < 3:
                    continue

                known_tools = [
                    "curl", "wget", "nmap", "nc", "netcat", "ncat",
                    "ssh", "sftp", "scp", "telnet", "ftp",
                    "dig", "nslookup", "whois", "host",
                    "gobuster", "wfuzz", "burp", "dirbuster",
                    "nikto", "sqlmap", "metasploit", "msfconsole",
                    "searchsploit", "git", "docker", "python", "bash",
                    "perl", "ruby", "node", "java", "powershell",
                    "crackmapexec", "impacket", "enum4linux", "rpcclient",
                    "smbclient", "ldapsearch", "nessus", "openvas",
                    "hydra", "john", "hashcat", "medusa",
                    "aircrack", "airmon", "hashcheck"
                ]
                first_token = stripped.split()[0].strip("`") if stripped.split() else ""
                first_token_base = first_token.split("/")[-1] if "/" in first_token else first_token

                if not any(first_token_base.lower().startswith(t) for t in known_tools):
                    continue

                cmd = stripped

            if not cmd:
                continue

            cmd = cmd.strip().strip("`")
            if re.search(r"<[^>]+>|SIGNATURE_HERE|YOUR_", cmd):
                continue
            if self._is_slow_nmap_command(cmd):
                continue
            if self._is_slow_tool(cmd):
                continue
            if self._is_local_only_command(cmd):
                continue
            if self._is_already_run_command(cmd):
                continue
            if not self._is_valid_command(cmd):
                continue

            cmd = strip_shell_operators(cmd)

            if cmd and cmd not in self.seen_commands and cmd not in self.skipped_commands:
                commands.append(cmd)
                self.seen_commands.add(cmd)

        return commands

    def extract_manual_steps(self, text: str) -> list[str]:
        steps = []
        current_lines: list[str] | None = None

        for line in text.splitlines():
            match = re.match(r"^\s*MANUAL:\s+(.+)", line)
            if match:
                if current_lines is not None:
                    steps.append(" ".join(current_lines).strip())
                current_lines = [match.group(1).strip()]
                continue

            if current_lines is not None:
                if re.match(r"^\s*(CMD:|Reason:|##|MANUAL:)", line) or line.strip() == "":
                    steps.append(" ".join(current_lines).strip())
                    current_lines = None
                elif re.match(r"^\s+", line):
                    current_lines.append(line.strip())

        if current_lines is not None:
            steps.append(" ".join(current_lines).strip())

        return [s for s in steps if s]

    def extract_domains(self, text: str) -> set[str]:
        domains = set()
        domain_pattern = re.compile(
            r'\b([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(?:\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\b'
        )

        for match in domain_pattern.finditer(text):
            domain = match.group(0).lower()
            if not self._is_valid_domain(domain):
                continue
            domains.add(domain)

        return domains

    def _is_valid_domain(self, domain: str) -> bool:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            return False

        if domain.endswith(('.txt', '.json', '.csv', '.sh', '.py', '.exe', '.bin')):
            return False
        if '/' in domain:
            return False

        if '.' not in domain:
            return False

        false_positives = {'localhost', 'example.com', 'test.com', 'domain.com', 'common'}
        if domain.lower() in false_positives:
            return False

        parts = domain.split('.')
        if all(p[0].isdigit() for p in parts if p):
            return False

        if len(parts) == 2 and parts[0].isdigit() and (parts[1][0].isdigit() or 'p' in parts[1] or 'v' in parts[1]):
            return False

        if not any(c.isalpha() for c in domain.replace('.', '')):
            return False

        if any(len(p) > 50 for p in parts):
            return False

        common_wordlist_names = {'xato', 'rockyou', 'common', 'dict', 'wordlist', 'list', 'usernames', 'passwords'}
        if any(name in domain.lower() for name in common_wordlist_names):
            return False

        return True

    def get_domain_context(self) -> str:
        if not self.discovered_domains:
            return ""
        domains_list = ", ".join(sorted(self.discovered_domains))
        return f"\nDiscovered domains to use in commands: {domains_list}"

    def replace_ip_with_domain(self, cmd: str, target_ip: str) -> str:
        if not self.discovered_domains or not target_ip:
            return cmd

        primary_domain = None
        for domain in sorted(self.discovered_domains):
            if domain.count('.') == 1 and 'htb' in domain:
                primary_domain = domain
                break

        if not primary_domain:
            for domain in sorted(self.discovered_domains):
                if domain.count('.') == 1:
                    primary_domain = domain
                    break

        if not primary_domain and self.discovered_domains:
            primary_domain = sorted(self.discovered_domains)[0]

        if primary_domain:
            cmd = cmd.replace(f"http://{target_ip}", f"http://{primary_domain}")
            cmd = cmd.replace(f"https://{target_ip}", f"https://{primary_domain}")
            cmd = cmd.replace(f"ssh://{target_ip}", f"ssh://{primary_domain}")
            cmd = cmd.replace(f"-h {target_ip}", f"-h {primary_domain}")
            cmd = cmd.replace(f"-H {target_ip}", f"-H {primary_domain}")
            cmd = re.sub(rf'\b{re.escape(target_ip)}\b', primary_domain, cmd)

        return cmd
