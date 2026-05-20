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
        temperature: float | None = 0.2,
        max_tokens: int | None = 4096,
        top_p: float | None = 0.95,
        top_k: int | None = 40,
        repeat_penalty: float | None = 1.1,
    ) -> str:
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
        }
        _add_sampling_params(payload, temperature, max_tokens, top_p, top_k, repeat_penalty)
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

    def chat_stream(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = 0.2,
        max_tokens: int | None = 4096,
        top_p: float | None = 0.95,
        top_k: int | None = 40,
        repeat_penalty: float | None = 1.1,
    ):
        url = f"{self.base_url.rstrip('/')}/chat/completions"
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
        }
        _add_sampling_params(payload, temperature, max_tokens, top_p, top_k, repeat_penalty)
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                in_reasoning = False
                for raw_line in response:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line or not line.startswith("data:"):
                        continue
                    payload_text = line.removeprefix("data:").strip()
                    if payload_text == "[DONE]":
                        break
                    try:
                        chunk = json.loads(payload_text)
                    except json.JSONDecodeError:
                        continue
                    try:
                        delta = chunk["choices"][0].get("delta", {})
                        content = delta.get("content") or ""
                        reasoning = (
                            delta.get("reasoning_content")
                            or delta.get("reasoning")
                            or delta.get("thinking")
                            or ""
                        )
                    except (KeyError, IndexError, TypeError):
                        content = ""
                        reasoning = ""
                    if reasoning:
                        if not in_reasoning:
                            yield "<think>"
                            in_reasoning = True
                        yield reasoning
                    if content:
                        if in_reasoning:
                            yield "</think>"
                            in_reasoning = False
                        yield content
                if in_reasoning:
                    yield "</think>"
        except urllib.error.URLError as exc:
            raise LlamaCppError(
                f"Could not reach llama.cpp at {url}. Is the server running?"
            ) from exc


def _add_sampling_params(
    payload: dict[str, Any],
    temperature: float | None,
    max_tokens: int | None,
    top_p: float | None,
    top_k: int | None,
    repeat_penalty: float | None,
) -> None:
    values = {
        "temperature": temperature,
        "max_tokens": max_tokens,
        "top_p": top_p,
        "top_k": top_k,
        "repeat_penalty": repeat_penalty,
    }
    for key, value in values.items():
        if value is not None:
            payload[key] = value
