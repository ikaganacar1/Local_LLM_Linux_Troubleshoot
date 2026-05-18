from __future__ import annotations

import os
import shutil
import shlex
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
    if os.environ.get("LTA_COMMAND_TARGET") == "host" and shutil.which("nsenter") is None:
        return CommandResult(
            command=command,
            exit_code=127,
            stdout="",
            stderr="Host command mode requires `nsenter` in the container and host PID access.",
        )

    try:
        return _run_plan(command, timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            command=command,
            exit_code=124,
            stdout=_decode_timeout_output(exc.stdout),
            stderr=_decode_timeout_output(exc.stderr)
            or f"Command timed out after {timeout_seconds} seconds.",
            timed_out=True,
        )
    except ValueError as exc:
        return CommandResult(command=command, exit_code=127, stdout="", stderr=str(exc))


def _decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _run_plan(command: str, timeout_seconds: int) -> CommandResult:
    groups = _parse_command(command)
    stdout_parts: list[str] = []
    stderr_parts: list[str] = []
    exit_code = 0
    for operator, pipeline in groups:
        if operator == "&&" and exit_code != 0:
            continue
        if operator == "||" and exit_code == 0:
            continue
        exit_code, stdout, stderr = _run_pipeline(pipeline, timeout_seconds)
        if stdout:
            stdout_parts.append(stdout)
        if stderr:
            stderr_parts.append(stderr)
    return CommandResult(
        command=command,
        exit_code=exit_code,
        stdout="".join(stdout_parts),
        stderr="".join(stderr_parts),
    )


def _parse_command(command: str) -> list[tuple[str, list[list[str]]]]:
    tokens = _shell_tokens(command)
    if not tokens:
        raise ValueError("Empty commands are not runnable.")

    groups: list[tuple[str, list[list[str]]]] = []
    operator = ";"
    pipeline: list[list[str]] = [[]]
    for token in tokens:
        if token in {"&&", "||", ";"}:
            _append_group(groups, operator, pipeline)
            operator = token
            pipeline = [[]]
        elif token == "|":
            if not pipeline[-1]:
                raise ValueError("Invalid empty pipeline segment.")
            pipeline.append([])
        elif _looks_like_redirection(token):
            raise ValueError(f"Shell redirection is not supported by the safe command runner: {token}")
        elif any(ch in token for ch in "|&;"):
            raise ValueError(f"Unsupported shell operator syntax: {token}")
        else:
            pipeline[-1].append(token)
    _append_group(groups, operator, pipeline)
    return groups


def _append_group(
    groups: list[tuple[str, list[list[str]]]],
    operator: str,
    pipeline: list[list[str]],
) -> None:
    if not pipeline or not pipeline[-1] or any(not segment for segment in pipeline):
        raise ValueError("Invalid empty command segment.")
    groups.append((operator, pipeline))


def _shell_tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;")
    lexer.whitespace_split = True
    return list(lexer)


def _looks_like_redirection(token: str) -> bool:
    if "<" in token or ">" in token:
        return True
    return len(token) >= 2 and token[:-1].isdigit() and token[-1] in {"<", ">"}


def _run_pipeline(pipeline: list[list[str]], timeout_seconds: int) -> tuple[int, str, str]:
    processes: list[subprocess.Popen[str]] = []
    previous_stdout = None
    for segment in pipeline:
        argv = _host_command_argv(segment)
        try:
            process = subprocess.Popen(
                argv,
                stdin=previous_stdout,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except OSError as exc:
            if previous_stdout is not None:
                previous_stdout.close()
            for running in processes:
                running.kill()
                running.communicate()
            return 127, "", f"{segment[0]}: {exc.strerror or str(exc)}"
        if previous_stdout is not None:
            previous_stdout.close()
        previous_stdout = process.stdout
        processes.append(process)

    try:
        stdout, stderr = processes[-1].communicate(timeout=timeout_seconds)
        stderr_parts = [stderr or ""]
        for process in processes[:-1]:
            _, segment_stderr = process.communicate(timeout=1)
            if segment_stderr:
                stderr_parts.append(segment_stderr)
    except subprocess.TimeoutExpired:
        for process in processes:
            process.kill()
        for process in processes:
            process.communicate()
        raise

    exit_code = processes[-1].returncode
    return exit_code, stdout or "", "".join(stderr_parts)


def _host_command_argv(argv: list[str]) -> list[str]:
    if os.environ.get("LTA_COMMAND_TARGET") != "host":
        return argv
    return [
        "nsenter",
        "--target",
        "1",
        "--mount",
        "--uts",
        "--ipc",
        "--net",
        "--pid",
        *argv,
    ]
