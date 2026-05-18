from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .llama_cpp_client import LlamaCppClient
from .prompts import build_system_prompt
from .safety import SafetyDecision, classify_command
from .shell import CommandResult, run_command


@dataclass
class Agent:
    config: Config
    client: LlamaCppClient
    messages: list[dict[str, str]] = field(default_factory=list)

    @classmethod
    def create(cls, config: Config) -> "Agent":
        client = LlamaCppClient(
            base_url=config.base_url,
            model=config.model,
            api_key=config.api_key,
        )
        return cls(
            config=config,
            client=client,
            messages=[{"role": "system", "content": build_system_prompt(config.system_prompt_path)}],
        )

    def add_user_message(self, content: str) -> None:
        self.messages.append({"role": "user", "content": content})

    def next_action(self) -> dict[str, Any]:
        raw = self.client.chat(self.messages)
        self.messages.append({"role": "assistant", "content": raw})
        return parse_action(raw)

    def record_command_result(self, result: CommandResult) -> None:
        self.messages.append(
            {
                "role": "user",
                "content": "Command output for analysis:\n\n" + result.format_for_model(),
            }
        )

    def record_controller_note(self, content: str) -> None:
        self.messages.append({"role": "user", "content": "Controller note: " + content})

    def handle_command(self, command: str) -> tuple[str, CommandResult | None]:
        safety = classify_command(command)
        if safety.decision == SafetyDecision.FORBIDDEN:
            note = f"Blocked forbidden command `{command}`: {safety.reason}"
            self.record_controller_note(note)
            return note, None

        if safety.decision == SafetyDecision.NEEDS_APPROVAL:
            return f"approval_required: {safety.reason}", None

        result = run_command(command, self.config.timeout_seconds)
        self.record_command_result(result)
        return "executed", result


def parse_action(raw: str) -> dict[str, Any]:
    text = raw.strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            return {"type": "message", "content": raw}
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError:
            return {"type": "message", "content": raw}

    if not isinstance(value, dict):
        return {"type": "message", "content": raw}
    if value.get("type") not in {"message", "command", "approval"}:
        return {"type": "message", "content": raw}
    return value
