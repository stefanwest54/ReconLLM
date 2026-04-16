"""analyst.py - LLM-powered penetration test analyst using the Claude API with streaming."""

import json
import os
import re
from typing import TYPE_CHECKING, Generator

import anthropic

if TYPE_CHECKING:
    from loot import Loot

_BASE_SYSTEM_PROMPT = """You are a senior offensive security specialist conducting an authorized penetration test.

Your analysis spans the full engagement kill chain, shifting naturally as the engagement progresses:

  RECON      — Map attack surface, identify versions/CVEs/misconfigs, prioritize vectors.
  FOOTHOLD   — Turn confirmed vulnerabilities or credentials into initial access.
  ESCALATION — Elevate from current access to root, SYSTEM, or domain admin.
  INTRUSION  — Lateral movement, data access, persistence, exfiltration paths.

Always state your current phase at the start of each response. Shift phases when the evidence warrants it — never speculate into a later phase without confirmation from results or loot.

Rules:
- Analyze only what is provided: scan results, command output, pasted content, loot, or direct questions.
- Tag findings by severity: [Critical] / [High] / [Medium] / [Low] / [Info]. Include CVE identifiers and CVSS scores where applicable.
- Every CMD must be immediately executable with a real CLI tool. No GUI-dependent commands.
- Suggest up to 8 CMDs in RECON, up to 6 in post-RECON phases, ordered by probability of success.
- Do not re-run scans already completed. Suggest only targeted follow-ups.
- Be direct and specific — no hedging, no theoretical discussion.
- Reference specific loot items (credentials, hashes, tokens) by name when they inform a command.
- If current evidence provides no clear forward path, say so and emit no CMD: lines.
- If the user asks a direct question, answer it concisely in context before returning to findings.

Command format (each on its own line):
CMD: <exact command>
Reason: <one-line rationale tied to a specific finding or loot item>

Output format:
## Phase: <RECON | FOOTHOLD | ESCALATION | INTRUSION | COMPLETE>

## Findings  (RECON phase)  /  ## Current Position  (post-RECON)
<findings with severity tags, or current access state and confirmed loot in play>

## Attack Path  (post-RECON only)
<direct reasoning: why this action, why now, expected outcome>

## Commands
CMD: ...
Reason: ..."""


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


_LOOT_EXTRACTION_MODEL = "claude-haiku-4-5-20251001"


def extract_loot_from_text(client: anthropic.Anthropic, model: str, text: str) -> dict:
    if not text or not text.strip():
        return {}

    prompt = (
        "Extract concrete security loot from the text below. "
        "Return ONLY a JSON object with this exact structure:\n"
        '{"credentials":[{"username":"","password":"","service":"","notes":""}],'
        '"hashes":[{"username":"","hash_value":"","hash_type":"","cracked":"","notes":""}],'
        '"tokens":[{"token_type":"","value":"","service":"","notes":""}],'
        '"shell_access":[{"method":"","user":"","host":"","notes":""}],'
        '"files":[{"path":"","description":"","notes":""}]}\n\n'
        "Extraction rules — be strict, only include items explicitly present in the text:\n"
        "- credentials: ONLY if BOTH a username AND its password/passphrase appear together.\n"
        "- hashes: ONLY actual hash strings (NTLM, bcrypt, MD5, SHA1, etc) with their username.\n"
        "- tokens: ONLY literal values — API keys, SSH private key blocks, JWT strings, session cookie values.\n"
        "- shell_access: ONLY if the text confirms a shell or interactive session was obtained.\n"
        "- files: ONLY paths to sensitive files that were read or confirmed to exist (configs, keys, etc).\n"
        "- If nothing qualifies, return empty arrays. Do NOT add analysis, CVEs, or observations.\n"
        "- Return ONLY the JSON object, no other text.\n\n"
        f"Text:\n{text[:6000]}"
    )

    try:
        response = client.messages.create(
            model=_LOOT_EXTRACTION_MODEL,
            max_tokens=1024,
            system="You extract structured security data. Return only valid JSON, no other text.",
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw.strip())
        return json.loads(raw)
    except Exception:
        return {}


class PenTestAnalyst:
    def __init__(self, model: str = "claude-opus-4-6", engagement_type: str = "pentest"):
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. "
                "Export it with: export ANTHROPIC_API_KEY='sk-ant-...'"
            )
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.system_prompt = _build_system_prompt(engagement_type)
        self.messages: list[dict] = []

    def _stream(self, user_content: str) -> Generator[str, None, None]:
        self.messages.append({"role": "user", "content": user_content})
        full_text = ""
        with self.client.messages.stream(
            model=self.model,
            max_tokens=8192,
            system=self.system_prompt,
            messages=self.messages,
        ) as stream:
            for text in stream.text_stream:
                full_text += text
                yield text
            final_msg = stream.get_final_message()

        self.messages.append({"role": "assistant", "content": final_msg.content})

    def _with_loot(self, loot: "Loot | None", content: str) -> str:
        if loot and not loot.is_empty():
            return f"{loot.summary()}\n\n{content}"
        return content

    def analyze_initial(self, scan_report: str) -> Generator[str, None, None]:
        prompt = (
            "Analyze the following initial reconnaissance results. "
            "Map the full attack surface: open ports, service versions, OS fingerprint, "
            "known CVEs for identified versions, and prioritized follow-up actions.\n\n"
            f"{scan_report}"
        )
        yield from self._stream(prompt)

    def analyze_initial_with_history(
        self, scan_report: str, prior_notes: str
    ) -> Generator[str, None, None]:
        prompt = (
            "You have prior engagement history for this target:\n\n"
            f"--- PRIOR NOTES ---\n{prior_notes}\n--- END PRIOR NOTES ---\n\n"
            "New scan results from this session:\n\n"
            f"{scan_report}\n\n"
            "Cross-reference the new results with the prior notes. Highlight any changes "
            "(new open ports, patched services, rotated credentials). Identify prior attack "
            "vectors that are still viable and any new ones introduced by changes. "
            "Map the complete updated attack surface and suggest prioritized follow-up actions."
        )
        yield from self._stream(prompt)

    def analyze_followup(
        self, followup_report: str, loot: "Loot | None" = None
    ) -> Generator[str, None, None]:
        prompt = self._with_loot(
            loot,
            f"Results from the last round:\n\n{followup_report}\n\n"
            "Update the current phase based on what was confirmed. "
            "If a phase transition is warranted, state it explicitly. "
            "Suggest the next highest-priority actions.",
        )
        yield from self._stream(prompt)

    def resume_from_notes(self, prior_notes: str) -> Generator[str, None, None]:
        prompt = (
            "Resuming engagement from prior session notes:\n\n"
            f"{prior_notes}\n\n"
            "Summarize the current state: what has been confirmed, what attack vectors are "
            "still open, and what was left unfinished. Then suggest the best next steps."
        )
        yield from self._stream(prompt)

    def analyze_freeform(
        self, user_input: str, loot: "Loot | None" = None
    ) -> Generator[str, None, None]:
        yield from self._stream(self._with_loot(loot, user_input))

    def generate_attack_summary(self) -> Generator[str, None, None]:
        prompt = (
            "Based on everything uncovered in this session, produce a concise structured summary "
            "to be saved as a reference for future sessions:\n\n"
            "## Confirmed Vulnerabilities\n"
            "List each with severity (Critical / High / Medium / Low) and CVE if known.\n\n"
            "## Recommended Attack Vectors\n"
            "Ordered by likelihood of success × impact. Be specific: include tool, target, "
            "and expected outcome for each vector.\n\n"
            "## Credentials / Hashes\n"
            "Any credentials, hashes, tokens, or keys recovered (or 'None found').\n\n"
            "## Remaining Unknowns\n"
            "Areas not yet fully enumerated or confirmed.\n\n"
            "## Quick Wins\n"
            "Lowest-effort, highest-impact next steps for the next session.\n\n"
            "Keep this tight and actionable — avoid restating raw scan output."
        )
        yield from self._stream(prompt)

    @staticmethod
    def extract_commands(text: str) -> list[str]:
        commands = []
        for line in text.splitlines():
            match = re.match(r"^\s*CMD:\s+(.+)", line)
            if match:
                cmd = match.group(1).strip()
                if cmd:
                    commands.append(cmd)
        return commands
