from __future__ import annotations

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
    try:
        completed = subprocess.run(
            command,
            shell=True,
            executable="/bin/bash",
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
            stdout=exc.stdout or "",
            stderr=exc.stderr or f"Command timed out after {timeout_seconds} seconds.",
            timed_out=True,
        )
