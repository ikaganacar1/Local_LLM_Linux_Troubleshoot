from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    def format_for_model(self, max_chars: int = 12000) -> str:
        output = (
            f"Command: {self.command}\n"
            f"Exit code: {self.exit_code}\n"
            f"Timed out: {self.timed_out}\n\n"
            f"STDOUT:\n{self.stdout or '(empty)'}\n\n"
            f"STDERR:\n{self.stderr or '(empty)'}"
        )
        if len(output) <= max_chars:
            return output
        return output[:max_chars] + "\n\n[output truncated]"


def run_command(command: str, timeout_seconds: int) -> CommandResult:
    argv = _host_command_argv(command)
    if os.environ.get("LTA_COMMAND_TARGET") == "host" and argv is None:
        return CommandResult(
            command=command,
            exit_code=127,
            stdout="",
            stderr="Host command mode requires `nsenter` in the container and host PID access.",
        )

    try:
        completed = subprocess.run(
            argv or command,
            shell=argv is None,
            executable="/bin/bash" if argv is None else None,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        return CommandResult(
            command=command,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command=command,
            exit_code=124,
            stdout=_decode_timeout_output(exc.stdout),
            stderr=_decode_timeout_output(exc.stderr)
            or f"Command timed out after {timeout_seconds} seconds.",
            timed_out=True,
        )


def _decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _host_command_argv(command: str) -> list[str] | None:
    if os.environ.get("LTA_COMMAND_TARGET") != "host":
        return None
    if shutil.which("nsenter") is None:
        return None
    return [
        "nsenter",
        "--target",
        "1",
        "--mount",
        "--uts",
        "--ipc",
        "--net",
        "--pid",
        "/bin/bash",
        "-lc",
        command,
    ]
