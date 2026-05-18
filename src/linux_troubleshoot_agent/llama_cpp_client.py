from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any


class LlamaCppError(RuntimeError):
    pass


@dataclass
class LlamaCppClient:
    base_url: str
    model: str
    api_key: str | None = None

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int = 900,
    ) -> str:
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise LlamaCppError(
                f"Could not reach llama.cpp at {url}. Is the server running?"
            ) from exc
        except json.JSONDecodeError as exc:
            raise LlamaCppError("llama.cpp returned invalid JSON.") from exc

        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LlamaCppError(f"Unexpected llama.cpp response: {body!r}") from exc
