import datetime
import os
import re

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

NOTES_DIR = os.path.join(os.path.dirname(__file__), "sessions")


def sanitize(target: str) -> str:
    """Sanitize a target name for use as a filename."""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', target)


def notes_path(target: str) -> str:
    """Get the path to the notes file for a target."""
    os.makedirs(NOTES_DIR, exist_ok=True)
    return os.path.join(NOTES_DIR, f"{sanitize(target)}.notes.txt")


def read_notes(target: str) -> str | None:
    """Return the full contents of a target's notes file, or None if it doesn't exist."""
    path = notes_path(target)
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return None


def write_session(target: str, session_text: str, engagement_type: str) -> str:
    """Write a session block to the target's notes file."""
    path = notes_path(target)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 62

    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("ReconLLM Target Notes\n")
            f.write(f"Target     : {target}\n")
            f.write(f"First seen : {timestamp}\n")
            f.write(f"{sep}\n")

    with open(path, "a") as f:
        f.write(f"\n{sep}\n")
        f.write(f"SESSION    : {timestamp}  |  type: {engagement_type}\n")
        f.write(f"{sep}\n\n")
        f.write(session_text.strip())
        f.write(f"\n\n{sep}\n")
        f.write(f"END SESSION\n")
        f.write(f"{sep}\n")

    return path


def autosave_path(target: str) -> str:
    """Get the path to the autosave file for a target."""
    os.makedirs(NOTES_DIR, exist_ok=True)
    return os.path.join(NOTES_DIR, f"{sanitize(target)}.autosave.txt")


def autosave_session(target: str, session_parts: list[str]) -> None:
    """Autosave session parts atomically (write-then-rename pattern)."""
    import tempfile

    path = autosave_path(target)
    content = _ANSI_ESCAPE.sub("", "\n\n".join(session_parts))

    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            dir=NOTES_DIR,
            delete=False,
            encoding='utf-8',
            suffix='.tmp'
        ) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        os.replace(tmp_path, path)
    except Exception as e:
        import sys
        print(
            f"\n[!] Failed to autosave session to {path}: {type(e).__name__}: {e}",
            file=sys.stderr
        )
        try:
            if 'tmp_path' in locals() and os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except:
            pass


def remove_autosave(target: str) -> None:
    """Remove the autosave file for a target."""
    path = autosave_path(target)
    if os.path.exists(path):
        try:
            os.unlink(path)
        except Exception as e:
            import sys
            print(f"[!] Failed to remove autosave {path}: {type(e).__name__}: {e}", file=sys.stderr)
