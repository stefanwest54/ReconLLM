"""notes.py - Persistent per-target session notes for ReconLLM."""

import datetime
import os
import re

NOTES_DIR = os.path.join(os.path.dirname(__file__), "sessions")


def sanitize(target: str) -> str:
    return re.sub(r"[^\w.\-]", "_", target)


def notes_path(target: str) -> str:
    os.makedirs(NOTES_DIR, exist_ok=True)
    return os.path.join(NOTES_DIR, f"{sanitize(target)}.txt")


def load_notes(target: str) -> str | None:
    path = notes_path(target)
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read()
    return None


def write_session(target: str, session_text: str, engagement_type: str) -> str:
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
