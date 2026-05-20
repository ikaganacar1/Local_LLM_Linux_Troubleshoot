from __future__ import annotations

import json
import os
import re
import unittest
import urllib.error
import urllib.request


APP_URL = os.environ.get("LTA_APP_URL", "http://127.0.0.1:28765").rstrip("/")
LLAMA_BASE_URL = os.environ.get("LTA_LLAMA_BASE_URL", "http://127.0.0.1:11435/v1").rstrip("/")
LIVE_MODEL = os.environ.get("LTA_LIVE_MODEL", "").strip()
HTTP_TIMEOUT = float(os.environ.get("LTA_LIVE_HTTP_TIMEOUT", "90"))
STREAM_TIMEOUT = float(os.environ.get("LTA_LIVE_STREAM_TIMEOUT", "240"))
MAX_TOKENS = int(os.environ.get("LTA_LIVE_MAX_TOKENS", "96"))


class LiveBackendLlmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.token = cls._load_browser_token()
        cls.models = cls._load_backend_models()
        cls.live_model = LIVE_MODEL or cls.models[0]["id"]

    @classmethod
    def _load_browser_token(cls) -> str:
        html = cls._request("GET", "/", timeout=HTTP_TIMEOUT)
        match = re.search(r'const authToken = "([^"]+)";', html)
        if not match:
            raise AssertionError("The served GUI did not embed an X-LTA-Token value.")
        return match.group(1)

    @classmethod
    def _headers(cls) -> dict[str, str]:
        headers = {"X-LTA-Token": cls.token}
        login = os.environ.get("LTA_LOGIN_TOKEN")
        if login:
            headers["X-LTA-Login"] = login
        return headers

    @classmethod
    def _request(
        cls,
        method: str,
        path: str,
        payload: dict | None = None,
        *,
        timeout: float,
    ) -> str:
        data = None
        headers = cls._headers() if hasattr(cls, "token") else {}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(APP_URL + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.URLError as exc:
            raise AssertionError(f"Could not reach app backend at {APP_URL}: {exc}") from exc

    def post_json(self, path: str, payload: dict, timeout: float = HTTP_TIMEOUT) -> dict:
        body = self._request("POST", path, payload, timeout=timeout)
        return json.loads(body)

    @classmethod
    def _load_backend_models(cls) -> list[dict]:
        body = cls._request(
            "POST",
            "/api/models",
            {"base_url": LLAMA_BASE_URL},
            timeout=HTTP_TIMEOUT,
        )
        data = json.loads(body)
        if not data.get("ok"):
            raise AssertionError(data.get("error") or "The app could not fetch llama.cpp models.")
        models = data.get("models") or []
        if not models:
            raise AssertionError("llama.cpp returned no model aliases through the app backend.")
        return models

    def test_app_state_api_is_available(self) -> None:
        data = json.loads(self._request("GET", "/api/state", timeout=HTTP_TIMEOUT))

        self.assertTrue(data["ok"])
        self.assertIn("settings", data)
        self.assertIn("memory", data)

    def test_llamacpp_models_endpoint_is_available_directly(self) -> None:
        request = urllib.request.Request(f"{LLAMA_BASE_URL}/models", method="GET")
        try:
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.URLError as exc:
            raise AssertionError(f"Could not reach llama.cpp at {LLAMA_BASE_URL}: {exc}") from exc

        self.assertGreater(len(data.get("data", [])), 0)

    def test_backend_can_fetch_llamacpp_models(self) -> None:
        self.assertGreater(len(self.models), 0)
        self.assertIn("id", self.models[0])

    def test_backend_can_fetch_llamacpp_model_defaults(self) -> None:
        data = self.post_json(
            "/api/model-defaults",
            {"base_url": LLAMA_BASE_URL, "model": self.live_model},
            timeout=HTTP_TIMEOUT,
        )

        self.assertTrue(data["ok"], data.get("error"))
        self.assertEqual(data["model"], self.live_model)
        self.assertIsInstance(data["parameters"], dict)

    def test_streaming_chat_round_trip_uses_local_llm(self) -> None:
        payload = {
            "base_url": LLAMA_BASE_URL,
            "model": self.live_model,
            "max_tokens": MAX_TOKENS,
            "temperature": 0,
            "top_p": 0.95,
            "top_k": 20,
            "repeat_penalty": 1.05,
            "message": (
                "Integration test only. Reply with a short normal message that says "
                "backend llm test ok. Do not request or run commands."
            ),
        }
        request = urllib.request.Request(
            APP_URL + "/api/message-stream",
            data=json.dumps(payload).encode("utf-8"),
            headers={**self._headers(), "Content-Type": "application/json"},
            method="POST",
        )

        events: list[dict] = []
        try:
            with urllib.request.urlopen(request, timeout=STREAM_TIMEOUT) as response:
                self.assertEqual(response.status, 200)
                for raw in response:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        events.append(json.loads(line))
        except urllib.error.URLError as exc:
            raise AssertionError(f"Streaming request failed: {exc}") from exc

        event_types = [event.get("type") for event in events]
        self.assertIn("session", event_types)
        self.assertNotIn("error", event_types, events)
        self.assertTrue(
            any(kind in {"token", "message"} for kind in event_types),
            f"No LLM content events received: {events}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
