from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    base_url: str
    model: str
    api_key: str | None
    system_prompt_path: Path | None
    timeout_seconds: int
    max_steps: int
    max_tokens: int
    temperature: float
    top_p: float
    top_k: int
    repeat_penalty: float

    @classmethod
    def from_env(cls) -> "Config":
        prompt_path = os.environ.get("LTA_SYSTEM_PROMPT")
        return cls(
            base_url=os.environ.get("LLAMA_CPP_BASE_URL", "http://127.0.0.1:11435/v1"),
            model=os.environ.get("LLAMA_CPP_MODEL", "local-model"),
            api_key=os.environ.get("LLAMA_CPP_API_KEY") or None,
            system_prompt_path=Path(prompt_path).expanduser() if prompt_path else None,
            timeout_seconds=int(os.environ.get("LTA_COMMAND_TIMEOUT", "30")),
            max_steps=int(os.environ.get("LTA_MAX_STEPS", "6")),
            max_tokens=int(os.environ.get("LTA_MAX_TOKENS", "4096")),
            temperature=float(os.environ.get("LTA_TEMPERATURE", "0.2")),
            top_p=float(os.environ.get("LTA_TOP_P", "0.95")),
            top_k=int(os.environ.get("LTA_TOP_K", "40")),
            repeat_penalty=float(os.environ.get("LTA_REPEAT_PENALTY", "1.1")),
        )
