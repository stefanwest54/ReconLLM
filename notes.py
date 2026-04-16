"""
notes.py - Persistent per-target session notes for ReconLLM.

Each unique target gets a single .txt file in the sessions/ directory.
New sessions are appended so the full engagement history accumulates over time.
"""

import datetime
import os
import re

NOTES_DIR = os.path.join(os.path.dirname(__file__), "sessions")


def sanitize(target: str) -> str:
    """Convert a target (IP, hostname, CIDR) into a safe filename stem."""
    return re.sub(r"[^\w.\-]", "_", target)


def notes_path(target: str) -> str:
    os.makedirs(NOTES_DIR, exist_ok=True)
    return os.path.join(NOTES_DIR, f"{sanitize(target)}.txt")


def load_notes(target: str) -> str | None:
    """Return the full contents of a target's notes file, or None if it doesn't exist."""
    path = notes_path(target)
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return None


def write_session(target: str, session_text: str, engagement_type: str) -> str:
    """
    Append a completed session block to the target's notes file.
    Creates the file with a header on first use.
    Returns the notes file path.
    """
    path = notes_path(target)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 62

    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(f"ReconLLM Target Notes\n")
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
