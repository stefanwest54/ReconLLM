""" scanner.py - Wrappers for ping and nmap scan execution. """
import platform
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass


def strip_shell_operators(cmd: str) -> str:
    cmd = re.sub(r'\s+(?:2>&1|2>/dev/null|>/dev/null|&1|>\S+|2>\S+)\s*$', '', cmd)
    cmd = re.sub(r'\s+(?:-o|-+output|-+out|-+results?)(?:=|\s+)\S+', '', cmd)

    preserve_pipe = False
    if '|' in cmd:
        pipe_tools = {'jq', 'grep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'head', 'tail', 'wc', 'tr'}
        for tool in pipe_tools:
            if f'| {tool}' in cmd or f'|{tool}' in cmd:
                preserve_pipe = True
                break
        if not preserve_pipe:
            cmd = cmd.split('|')[0].strip()

    if '<(' in cmd:
        cmd = cmd.split('<(')[0].strip()
    for op in (' && ', ' || ', '; '):
        if op in cmd:
            cmd = cmd.split(op)[0].strip()
    return cmd.strip()


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
    if platform.system().lower() == "windows":
        cmd = f"ping -n {count} {host}"
    else:
        cmd = f"ping -c {count} {host}"

    return run_command(cmd, timeout=15)


def nmap_scan(target: str, args: str = "-sV") -> ScanResult:
    cmd = f"nmap {args} {target}"
    return run_command(cmd, timeout=90)


def run_command(cmd: str, timeout: int = 60, stop_event=None) -> ScanResult:
    tool_name = cmd.split()[0] if cmd.split() else "unknown"
    use_shell = False
    pipe_tools = {'jq', 'grep', 'awk', 'sed', 'cut', 'sort', 'uniq', 'head', 'tail', 'wc', 'tr'}
    if '|' in cmd:
        for tool in pipe_tools:
            if f'| {tool}' in cmd or f'|{tool}' in cmd:
                use_shell = True
                break

    if use_shell:
        args = cmd
    else:
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
                if use_shell:
                    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                else:
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
                    stderr=f"Command timed out after {timeout} seconds.",
                    returncode=1
                )
        else:
            if use_shell:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
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
