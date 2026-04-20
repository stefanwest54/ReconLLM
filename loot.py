""" loot.py - Structured loot tracking for ReconLLM. """
import datetime
import json
import os
import re
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
    seen_commands: list[str] = field(default_factory=list)
    skipped_commands: list[str] = field(default_factory=list)

    def __post_init__(self):
        self._rebuild_dedup_cache()

    def _rebuild_dedup_cache(self) -> None:
        self._cred_cache: set[tuple[str, str]] = set(
            (c.username, c.password) for c in self.credentials
        )
        self._hash_cache: set[str] = set(h.hash_value for h in self.hashes)
        self._token_cache: set[str] = set(t.value for t in self.tokens)
        self._shell_cache: set[tuple[str, str]] = set(
            (s.method, s.user) for s in self.shell_access
        )
        self._file_cache: set[str] = set(f.path for f in self.files)

    def _is_junk(self, text: str) -> bool:
        if not text or len(text) < 2:
            return True

        lower = text.lower()

        if lower in ["unknown", "n/a", "none", "null", "---", "...", "?"]:
            return True
        if re.match(r"^<[^>]+>$|SIGNATURE_HERE|YOUR_|PLACEHOLDER", text, re.I):
            return True

        if lower in ["admin", "root", "test", "user", "guest", "default", "administrator",
                     "system", "service", "nobody", "operator", "bin", "daemon", "sync",
                     "shutdown", "halt", "mail", "news", "uucp", "games", "mysql", "postgres"]:
            return True

        if lower in ["password", "pass", "pwd", "123456", "password123", "admin123",
                     "letmein", "welcome", "secret", "qwerty", "12345678"]:
            return True

        if len(text) < 8 and re.match(r"^[a-zA-Z0-9]+$", text):
            return True

        if lower in ["http", "https", "ssh", "ftp", "smtp", "pop3", "imap", "telnet",
                     "dns", "dhcp", "ldap", "kerberos", "vnc", "rdp", "smb", "nfs",
                     "ntp", "snmp", "syslog"]:
            return True

        if lower in ["/etc/passwd", "/etc/shadow", "/etc/hosts", "/root", "/home",
                     "localhost", "127.0.0.1", "0.0.0.0"]:
            return True

        analysis_patterns = [
            "target appears", "api endpoint", "http", "curl", "command", "response",
            "server", "request", "exit code", "endpoint", "no credentials", "no valid",
            "endpoint accessed", "request method", "endpoint returned", "http method",
            "successful", "executed", "found in", "contains", "returned", "detected"
        ]
        for pattern in analysis_patterns:
            if lower.startswith(pattern):
                return True

        return False

    def is_empty(self) -> bool:
        return not any([
            self.credentials,
            self.hashes,
            self.tokens,
            self.shell_access,
            self.files,
            self.notes,
        ])

    def summary(self) -> str:
        lines = []
        if self.credentials:
            lines.append(f"  Credentials: {len(self.credentials)}")
            for c in self.credentials:
                service = f" ({c.service})" if c.service else ""
                lines.append(f"    • {c.username}:{c.password}{service}")
        if self.hashes:
            lines.append(f"  Hashes: {len(self.hashes)}")
            for h in self.hashes:
                h_type = f" [{h.hash_type}]" if h.hash_type else ""
                cracked = f" → {h.cracked}" if h.cracked else ""
                lines.append(f"    • {h.username}{h_type}: {h.hash_value[:50]}...{cracked}")
        if self.tokens:
            lines.append(f"  Tokens: {len(self.tokens)}")
            for t in self.tokens:
                service = f" ({t.service})" if t.service else ""
                lines.append(f"    • {t.token_type}{service}: {t.value[:40]}...")
        if self.shell_access:
            lines.append(f"  Shell Access: {len(self.shell_access)}")
            for s in self.shell_access:
                lines.append(f"    • {s.method} @ {s.host} as {s.user}")
        if self.files:
            lines.append(f"  Files: {len(self.files)}")
            for f in self.files:
                desc = f" — {f.description}" if f.description else ""
                lines.append(f"    • {f.path}{desc}")
        if self.notes:
            lines.append(f"  Notes: {len(self.notes)}")
            for n in self.notes:
                lines.append(f"    • {n}")
        return "\n".join(lines) if lines else "  (no loot captured)"

    def new_items_since(self, previous: "Loot") -> "Loot":
        new = Loot(target=self.target)

        prev_cred_cache = set((c.username, c.password) for c in previous.credentials)
        new.credentials = [c for c in self.credentials if (c.username, c.password) not in prev_cred_cache]

        prev_hash_cache = set(h.hash_value for h in previous.hashes)
        new.hashes = [h for h in self.hashes if h.hash_value not in prev_hash_cache]

        prev_token_cache = set(t.value for t in previous.tokens)
        new.tokens = [t for t in self.tokens if t.value not in prev_token_cache]

        prev_shell_cache = set((s.method, s.user) for s in previous.shell_access)
        new.shell_access = [s for s in self.shell_access if (s.method, s.user) not in prev_shell_cache]

        prev_file_cache = set(f.path for f in previous.files)
        new.files = [f for f in self.files if f.path not in prev_file_cache]

        prev_notes = set(previous.notes)
        new.notes = [n for n in self.notes if n not in prev_notes]

        return new

    def save(self) -> None:
        save_loot(self)

    def merge(self, extracted: dict) -> int:
        count = 0

        for item in extracted.get("credentials", []):
            try:
                cred = Credential(**item)
                cred_key = (cred.username, cred.password)
                if (cred.username and cred.password
                        and not self._is_junk(cred.username)
                        and not self._is_junk(cred.password)
                        and cred_key not in self._cred_cache):
                    self.credentials.append(cred)
                    self._cred_cache.add(cred_key)
                    count += 1
            except (TypeError, ValueError):
                continue

        for item in extracted.get("hashes", []):
            try:
                h = Hash(**item)
                if (h.hash_value
                        and not self._is_junk(h.hash_value)
                        and h.hash_value not in self._hash_cache):
                    self.hashes.append(h)
                    self._hash_cache.add(h.hash_value)
                    count += 1
            except (TypeError, ValueError):
                continue

        for item in extracted.get("tokens", []):
            try:
                t = Token(**item)
                if (t.value
                        and not self._is_junk(t.value)
                        and t.value not in self._token_cache):
                    self.tokens.append(t)
                    self._token_cache.add(t.value)
                    count += 1
            except (TypeError, ValueError):
                continue

        for item in extracted.get("shell_access", []):
            try:
                s = ShellAccess(**item)
                shell_key = (s.method, s.user)
                if (s.method and s.user
                        and not self._is_junk(s.method)
                        and not self._is_junk(s.user)
                        and shell_key not in self._shell_cache):
                    self.shell_access.append(s)
                    self._shell_cache.add(shell_key)
                    count += 1
            except (TypeError, ValueError):
                continue

        for item in extracted.get("files", []):
            try:
                f = LootFile(**item)
                if (f.path
                        and not self._is_junk(f.path)
                        and f.path not in self._file_cache):
                    self.files.append(f)
                    self._file_cache.add(f.path)
                    count += 1
            except (TypeError, ValueError):
                continue

        for note in extracted.get("notes", []):
            if note and note not in self.notes:
                self.notes.append(note)

        self.last_updated = datetime.datetime.now().isoformat()

        return count


def _loot_path(target: str) -> str:
    os.makedirs(NOTES_DIR, exist_ok=True)
    return os.path.join(NOTES_DIR, f"{sanitize(target)}.loot.json")


def load_loot(target: str) -> Loot:
    path = _loot_path(target)
    if not os.path.exists(path):
        return Loot(target=target)

    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        import sys
        print(
            f"\n[!] Corrupted loot file {path}: {e}\n"
            f"    Starting with fresh loot for this session.",
            file=sys.stderr
        )
        return Loot(target=target)
    except UnicodeDecodeError as e:
        import sys
        print(
            f"\n[!] Loot file encoding error {path}: {e}\n"
            f"    Starting with fresh loot for this session.",
            file=sys.stderr
        )
        return Loot(target=target)
    except Exception as e:
        import sys
        print(
            f"\n[!] Failed to load loot file {path}: {type(e).__name__}: {e}\n"
            f"    Starting with fresh loot for this session.",
            file=sys.stderr
        )
        return Loot(target=target)

    try:
        loot = Loot(
            target=data.get("target", target),
            last_updated=data.get("last_updated", ""),
            notes=data.get("notes", []),
            seen_commands=data.get("seen_commands", []),
            skipped_commands=data.get("skipped_commands", []),
        )
        for item in data.get("credentials", []):
            try:
                loot.credentials.append(Credential(**item))
            except TypeError:
                continue
        for item in data.get("hashes", []):
            try:
                loot.hashes.append(Hash(**item))
            except TypeError:
                continue
        for item in data.get("tokens", []):
            try:
                loot.tokens.append(Token(**item))
            except TypeError:
                continue
        for item in data.get("shell_access", []):
            try:
                loot.shell_access.append(ShellAccess(**item))
            except TypeError:
                continue
        for item in data.get("files", []):
            try:
                loot.files.append(LootFile(**item))
            except TypeError:
                continue
        loot._rebuild_dedup_cache()
        return loot
    except Exception as e:
        import sys
        print(
            f"\n[!] Error parsing loot items from {path}: {type(e).__name__}: {e}\n"
            f"    Starting with fresh loot for this session.",
            file=sys.stderr
        )
        return Loot(target=target)


def save_loot(loot: Loot) -> None:
    import tempfile
    path = _loot_path(loot.target)

    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            dir=NOTES_DIR,
            delete=False,
            encoding='utf-8',
            suffix='.tmp'
        ) as tmp:
            json.dump(asdict(loot), tmp, indent=2)
            tmp_path = tmp.name

        os.replace(tmp_path, path)
    except Exception as e:
        import sys
        print(
            f"\n[!] Failed to save loot to {path}: {type(e).__name__}: {e}",
            file=sys.stderr
        )
        try:
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except:
            pass
        raise
