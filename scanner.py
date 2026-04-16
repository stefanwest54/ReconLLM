import platform
import shlex
import shutil
import subprocess
import time
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
    """Ping a host to check if it's reachable."""
    if platform.system().lower() == "windows":
        cmd = f"ping -n {count} {host}"
    else:
        cmd = f"ping -c {count} {host}"

    return run_command(cmd, timeout=15)


def nmap_scan(target: str, args: str = "-sV") -> ScanResult:
    """
    Run an nmap scan against the target with the given argument string.
    Timeout is 90 seconds — broad/slow scans will be rejected by the analyst.
    """
    cmd = f"nmap {args} {target}"
    return run_command(cmd, timeout=90)


def run_command(cmd: str, timeout: int = 60, stop_event=None) -> ScanResult:
    """
    Execute a follow-up command suggested by the analyst.
    Uses shlex.split for safe argument parsing — does NOT invoke a shell.
    Pass a threading.Event as stop_event to allow the caller to kill mid-run.
    Timeout is 60 seconds by default — tools that hang longer are blocked.
    """
    tool_name = cmd.split()[0] if cmd.split() else "unknown"

    try:
        args = shlex.split(cmd)
    except ValueError as e:
        return ScanResult(
            tool=tool_name,
            target="",
            command=cmd,
            stdout="",
            stderr=f"Failed to parse command: {e}",
            returncode=1
        )

    if not shutil.which(args[0]):
        return ScanResult(
            tool=tool_name,
            target="",
            command=cmd,
            stdout="",
            stderr=f"Command not found: {args[0]}",
            returncode=127
        )

    try:
        if not stop_event:
            try:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = proc.communicate(timeout=timeout)
                return ScanResult(
                    tool=tool_name,
                    target="",
                    command=cmd,
                    stdout=stdout.decode('utf-8', errors='replace') if stdout else "",
                    stderr=stderr.decode('utf-8', errors='replace') if stderr else "",
                    returncode=proc.returncode
                )
            except subprocess.TimeoutExpired as e:
                return ScanResult(
                    tool=tool_name,
                    target="",
                    command=cmd,
                    stdout="",
                    stderr=f"nmap timed out after {timeout} seconds. Scope nmap to fewer ports or specific hosts.",
                    returncode=1
                )
        else:
            proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.time() + timeout
            poll_interval = 0.2

            while True:
                if stop_event.is_set():
                    proc.kill()
                    try:
                        stdout, stderr = proc.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.wait(timeout=1)
                        stdout, stderr = b"", b"Process killed by stop_event"
                    return ScanResult(
                        tool=tool_name,
                        target="",
                        command=cmd,
                        stdout=stdout.decode('utf-8', errors='replace') if stdout else "",
                        stderr=stderr.decode('utf-8', errors='replace') if stderr else "",
                        returncode=-1
                    )

                ret = proc.poll()
                if ret is not None:
                    stdout, stderr = proc.communicate(timeout=1)
                    return ScanResult(
                        tool=tool_name,
                        target="",
                        command=cmd,
                        stdout=stdout.decode('utf-8', errors='replace') if stdout else "",
                        stderr=stderr.decode('utf-8', errors='replace') if stderr else "",
                        returncode=ret
                    )

                if time.time() > deadline:
                    proc.kill()
                    try:
                        stdout, stderr = proc.communicate(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.wait(timeout=1)
                        stdout, stderr = b"", b"Timeout"
                    return ScanResult(
                        tool=tool_name,
                        target="",
                        command=cmd,
                        stdout=stdout.decode('utf-8', errors='replace') if stdout else "",
                        stderr=stderr.decode('utf-8', errors='replace') if stderr else "",
                        returncode=1
                    )

                time.sleep(poll_interval)

    except OSError as e:
        return ScanResult(
            tool=tool_name,
            target="",
            command=cmd,
            stdout="",
            stderr=f"OSError: {e}",
            returncode=1
        )
    except Exception as e:
        return ScanResult(
            tool=tool_name,
            target="",
            command=cmd,
            stdout="",
            stderr=f"{type(e).__name__}: {e}",
            returncode=1
        )
