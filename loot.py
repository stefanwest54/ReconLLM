""" loot.py - Structured loot tracking for ReconLLM."""

import datetime
import json
import os
from dataclasses import asdict, dataclass, field

from notes import NOTES_DIR, sanitize


@dataclass
class Credential:
    username: str
    password: str
    service: str = ""
    notes: str = ""


@dataclass
class Hash:
    username: str
    hash_value: str
    hash_type: str = ""
    cracked: str = ""
    notes: str = ""


@dataclass
class Token:
    token_type: str
    value: str
    service: str = ""
    notes: str = ""


@dataclass
class ShellAccess:
    method: str
    user: str
    host: str
    notes: str = ""


@dataclass
class LootFile:
    path: str
    description: str = ""
    notes: str = ""


@dataclass
class Loot:
    target: str
    credentials: list[Credential] = field(default_factory=list)
    hashes: list[Hash] = field(default_factory=list)
    tokens: list[Token] = field(default_factory=list)
    shell_access: list[ShellAccess] = field(default_factory=list)
    files: list[LootFile] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    last_updated: str = ""

    def is_empty(self) -> bool:
        return not any([
            self.credentials, self.hashes, self.tokens,
            self.shell_access, self.files, self.notes,
        ])

    def summary(self) -> str:
        if self.is_empty():
            return "No loot captured yet."

        lines = ["=== CURRENT LOOT ==="]

        if self.credentials:
            lines.append("\n[Credentials]")
            for c in self.credentials:
                s = f"  {c.username}:{c.password}"
                if c.service:
                    s += f" ({c.service})"
                if c.notes:
                    s += f" — {c.notes}"
                lines.append(s)

        if self.hashes:
            lines.append("\n[Hashes]")
            for h in self.hashes:
                s = f"  {h.username}: {h.hash_value}"
                if h.hash_type:
                    s += f" [{h.hash_type}]"
                if h.cracked:
                    s += f" (cracked: {h.cracked})"
                if h.notes:
                    s += f" — {h.notes}"
                lines.append(s)

        if self.tokens:
            lines.append("\n[Tokens / Keys]")
            for t in self.tokens:
                val = t.value[:80] + ("..." if len(t.value) > 80 else "")
                s = f"  [{t.token_type}] {val}"
                if t.service:
                    s += f" ({t.service})"
                lines.append(s)

        if self.shell_access:
            lines.append("\n[Shell Access]")
            for s in self.shell_access:
                line = f"  {s.user}@{s.host} via {s.method}"
                if s.notes:
                    line += f" — {s.notes}"
                lines.append(line)

        if self.files:
            lines.append("\n[Sensitive Files]")
            for f in self.files:
                s = f"  {f.path}"
                if f.description:
                    s += f" — {f.description}"
                lines.append(s)


        if self.last_updated:
            lines.append(f"\nLast updated: {self.last_updated}")
        lines.append("=== END LOOT ===")
        return "\n".join(lines)

    def merge(self, extracted: dict) -> int:
        count = 0

        for item in extracted.get("credentials", []):
            cred = Credential(
                username=item.get("username", ""),
                password=item.get("password", ""),
                service=item.get("service", ""),
                notes=item.get("notes", ""),
            )
            if cred.username and cred.password:
                if not any(
                    c.username == cred.username and c.password == cred.password
                    for c in self.credentials
                ):
                    self.credentials.append(cred)
                    count += 1

        for item in extracted.get("hashes", []):
            h = Hash(
                username=item.get("username", ""),
                hash_value=item.get("hash_value", ""),
                hash_type=item.get("hash_type", ""),
                cracked=item.get("cracked", ""),
                notes=item.get("notes", ""),
            )
            if h.hash_value:
                if not any(x.hash_value == h.hash_value for x in self.hashes):
                    self.hashes.append(h)
                    count += 1

        for item in extracted.get("tokens", []):
            t = Token(
                token_type=item.get("token_type", ""),
                value=item.get("value", ""),
                service=item.get("service", ""),
                notes=item.get("notes", ""),
            )
            if t.value:
                if not any(x.value == t.value for x in self.tokens):
                    self.tokens.append(t)
                    count += 1

        for item in extracted.get("shell_access", []):
            s = ShellAccess(
                method=item.get("method", ""),
                user=item.get("user", ""),
                host=item.get("host", ""),
                notes=item.get("notes", ""),
            )
            if s.method and s.user:
                if not any(
                    x.method == s.method and x.user == s.user
                    for x in self.shell_access
                ):
                    self.shell_access.append(s)
                    count += 1

        for item in extracted.get("files", []):
            lf = LootFile(
                path=item.get("path", ""),
                description=item.get("description", ""),
                notes=item.get("notes", ""),
            )
            if lf.path:
                if not any(x.path == lf.path for x in self.files):
                    self.files.append(lf)
                    count += 1

        if count > 0:
            self.last_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return count


def _loot_path(target: str) -> str:
    os.makedirs(NOTES_DIR, exist_ok=True)
    return os.path.join(NOTES_DIR, f"{sanitize(target)}.loot.json")


def load_loot(target: str) -> Loot:
    path = _loot_path(target)
    if not os.path.exists(path):
        return Loot(target=target)
    with open(path) as f:
        data = json.load(f)
    loot = Loot(
        target=data.get("target", target),
        last_updated=data.get("last_updated", ""),
        notes=data.get("notes", []),
    )
    for item in data.get("credentials", []):
        loot.credentials.append(Credential(**item))
    for item in data.get("hashes", []):
        loot.hashes.append(Hash(**item))
    for item in data.get("tokens", []):
        loot.tokens.append(Token(**item))
    for item in data.get("shell_access", []):
        loot.shell_access.append(ShellAccess(**item))
    for item in data.get("files", []):
        loot.files.append(LootFile(**item))
    return loot


def save_loot(loot: Loot) -> None:
    path = _loot_path(loot.target)
    with open(path, "w") as f:
        json.dump(asdict(loot), f, indent=2)
