"""
scanner.py - Wrappers for ping and nmap scan execution.
"""

import platform
import shlex
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ScanResult:
    tool: str
    target: str
    command: str
    stdout: str
    stderr: str
    returncode: int

    @property
    def success(self) -> bool:
        return self.returncode == 0

    def to_report(self) -> str:
        lines = [
            f"=== {self.tool.upper()} RESULTS ===",
            f"Target  : {self.target}",
            f"Command : {self.command}",
            f"Exit    : {self.returncode}",
            "",
        ]
        if self.stdout:
            lines.append(self.stdout.strip())
        if self.stderr:
            lines.append(f"[STDERR]\n{self.stderr.strip()}")
        return "\n".join(lines)


def ping_host(host: str, count: int = 4) -> ScanResult:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), host]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return ScanResult(
            tool="ping",
            target=host,
            command=" ".join(cmd),
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return ScanResult(
            tool="ping", target=host, command=" ".join(cmd),
            stdout="", stderr="Ping timed out after 30 seconds.", returncode=1,
        )
    except FileNotFoundError:
        return ScanResult(
            tool="ping", target=host, command=" ".join(cmd),
            stdout="", stderr="ping not found in PATH.", returncode=127,
        )


def nmap_scan(target: str, args: str = "-sV -T4 --top-ports 1000") -> ScanResult:
    if not shutil.which("nmap"):
        return ScanResult(
            tool="nmap", target=target, command="nmap (not found)",
            stdout="",
            stderr="nmap not found in PATH. Install with: sudo apt install nmap",
            returncode=127,
        )

    cmd = ["nmap"] + shlex.split(args) + [target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return ScanResult(
            tool="nmap",
            target=target,
            command=" ".join(cmd),
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
        )
    except subprocess.TimeoutExpired:
        return ScanResult(
            tool="nmap", target=target, command=" ".join(cmd),
            stdout="", stderr="nmap timed out after 600 seconds.", returncode=1,
        )


def run_command(command: str, timeout: int = 180, stop_event=None) -> ScanResult:
    import time

    try:
        parts = shlex.split(command)
    except ValueError as e:
        return ScanResult(
            tool="unknown", target=command, command=command,
            stdout="", stderr=f"Failed to parse command: {e}", returncode=1,
        )

    tool = parts[0] if parts else "unknown"

    if not shutil.which(tool):
        return ScanResult(
            tool=tool, target=command, command=command,
            stdout="", stderr=f"'{tool}' not found in PATH.", returncode=127,
        )

    try:
        proc = subprocess.Popen(parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except Exception as e:
        return ScanResult(
            tool=tool, target=command, command=command,
            stdout="", stderr=str(e), returncode=1,
        )

    deadline = time.time() + timeout
    try:
        while True:
            ret = proc.poll()
            if ret is not None:
                stdout, stderr = proc.communicate()
                return ScanResult(
                    tool=tool, target=command, command=command,
                    stdout=stdout, stderr=stderr, returncode=ret,
                )
            if stop_event and stop_event.is_set():
                proc.kill()
                stdout, stderr = proc.communicate()
                return ScanResult(
                    tool=tool, target=command, command=command,
                    stdout=stdout, stderr=stderr, returncode=-1,
                )
            if time.time() > deadline:
                proc.kill()
                proc.communicate()
                return ScanResult(
                    tool=tool, target=command, command=command,
                    stdout="", stderr=f"Command timed out after {timeout}s.", returncode=1,
                )
            time.sleep(0.05)
    except Exception:
        proc.kill()
        proc.communicate()
        raise
