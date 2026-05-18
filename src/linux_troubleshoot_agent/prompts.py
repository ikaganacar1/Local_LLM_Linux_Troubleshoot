from __future__ import annotations

from importlib.resources import files
from pathlib import Path


CONTROLLER_PROMPT = """
You are controlled by a local command runner. For every response, output exactly one JSON object and no markdown.

Valid response shapes:
{"type":"message","content":"short user-facing answer"}
{"type":"command","reason":"why this read-only command helps","command":"single shell command"}
{"type":"approval","reason":"why this modifying command is needed","command":"single shell command"}

Rules:
- Use "command" only for read-only diagnostics.
- Use "approval" for installs, removals, edits, service changes, reboots, killing processes, or anything uncertain.
- Ask for one command at a time.
- Prefer the smallest useful diagnostic command.
- After command output is provided, summarize the meaning and choose the next minimal step.
""".strip()


def load_system_prompt(path: Path | None = None) -> str:
    if path is not None:
        return path.read_text(encoding="utf-8").strip()

    repo_prompt = Path.cwd() / "prompts" / "system_prompt.txt"
    if repo_prompt.exists():
        return repo_prompt.read_text(encoding="utf-8").strip()

    return files("linux_troubleshoot_agent").joinpath("default_system_prompt.txt").read_text(
        encoding="utf-8"
    ).strip()


def build_system_prompt(path: Path | None = None) -> str:
    return f"{load_system_prompt(path)}\n\n{CONTROLLER_PROMPT}"
