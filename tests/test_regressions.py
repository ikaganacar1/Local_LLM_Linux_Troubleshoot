from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from linux_troubleshoot_agent.safety import SafetyDecision, classify_command
from linux_troubleshoot_agent.shell import run_command
from linux_troubleshoot_agent.storage import PermissionSettings, save_settings
from linux_troubleshoot_agent.web import (
    SESSIONS,
    WebSession,
    _permission_allows_command,
    handle_approval,
    handle_action,
    handle_model_defaults,
)


class SafetyRegressionTests(unittest.TestCase):
    def test_shell_substitution_requires_approval(self) -> None:
        result = classify_command("ls $(touch ~/.pwned)")
        self.assertEqual(result.decision, SafetyDecision.NEEDS_APPROVAL)

    def test_glued_shell_operators_do_not_hide_modifying_commands(self) -> None:
        for command in (
            "cat /etc/os-release; touch ~/.pwned",
            "uname -a&&touch ~/.pwned",
            "cat /etc/os-release||touch ~/.pwned",
        ):
            with self.subTest(command=command):
                result = classify_command(command)
                self.assertEqual(result.decision, SafetyDecision.NEEDS_APPROVAL)

    def test_quoted_shell_operators_can_still_be_read_only_arguments(self) -> None:
        result = classify_command("sed -n '1;3p' /etc/os-release")
        self.assertEqual(result.decision, SafetyDecision.SAFE)

    def test_forbidden_command_after_web_approval_is_blocked(self) -> None:
        notes: list[str] = []
        agent = SimpleNamespace(
            config=SimpleNamespace(timeout_seconds=1),
            record_controller_note=notes.append,
        )
        SESSIONS["regression"] = WebSession(agent=agent, pending_command="rm -rf /")

        response = handle_approval({"session_id": "regression", "approved": True})

        self.assertTrue(response["ok"])
        self.assertEqual(response["events"][0]["type"], "blocked")
        self.assertTrue(notes[-1].startswith("Blocked forbidden command"))

    def test_package_update_permission_does_not_allow_remove(self) -> None:
        settings = PermissionSettings(
            allow_package_updates=True,
            require_confirmation_for_modifying=False,
        )

        self.assertFalse(_permission_allows_command("apt remove vim", settings))
        self.assertTrue(
            _permission_allows_command("sudo apt update && sudo apt upgrade -y", settings)
        )

    def test_timeout_output_is_json_serializable(self) -> None:
        result = run_command("printf hi; sleep 2", 1)

        self.assertTrue(result.timed_out)
        self.assertIsInstance(result.stdout, str)
        self.assertIsInstance(result.stderr, str)
        json.dumps({"stdout": result.stdout, "stderr": result.stderr})

    def test_module_preserves_forbidden_exit_code(self) -> None:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "linux_troubleshoot_agent",
                "--check-command",
                "rm -rf /",
            ],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 2)


class WebRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_data_dir = os.environ.get("LTA_DATA_DIR")
        self._old_host_home = os.environ.get("LTA_HOST_HOME")
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        os.environ["LTA_DATA_DIR"] = str(root / "data")
        os.environ["LTA_HOST_HOME"] = str(root / "home")
        Path(os.environ["LTA_HOST_HOME"]).mkdir()
        SESSIONS.clear()

    def tearDown(self) -> None:
        SESSIONS.clear()
        if self._old_data_dir is None:
            os.environ.pop("LTA_DATA_DIR", None)
        else:
            os.environ["LTA_DATA_DIR"] = self._old_data_dir
        if self._old_host_home is None:
            os.environ.pop("LTA_HOST_HOME", None)
        else:
            os.environ["LTA_HOST_HOME"] = self._old_host_home
        self._tmp.cleanup()

    def test_action_skip_declines_confirmation_instead_of_reprompting(self) -> None:
        save_settings(
            PermissionSettings(
                allow_personal_folder_organize=True,
                require_confirmation_for_modifying=True,
            )
        )

        prompted = handle_action({"session_id": "skip-test", "action": "organize_apply"})
        self.assertEqual(prompted["events"][0]["type"], "action_confirmation")

        skipped = handle_action(
            {"session_id": "skip-test", "action": "organize_apply", "confirmed": False}
        )
        self.assertTrue(skipped["ok"])
        self.assertEqual(skipped["events"][0]["type"], "notice")
        self.assertIn("skipped", skipped["events"][0]["content"].lower())

    def test_model_defaults_are_loaded_from_llamacpp_props(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "default_generation_settings": {
                            "max_tokens": -1,
                            "temperature": 0.7,
                            "top_p": 0.88,
                            "top_k": 64,
                            "repeat_penalty": 1.08,
                        }
                    }
                ).encode("utf-8")

        requested_urls: list[str] = []

        def fake_urlopen(request, timeout=0):
            requested_urls.append(request.full_url)
            return FakeResponse()

        with patch("linux_troubleshoot_agent.web.urllib.request.urlopen", fake_urlopen):
            response = handle_model_defaults(
                {
                    "base_url": "http://127.0.0.1:11435/v1",
                    "model": "test model",
                }
            )

        self.assertTrue(response["ok"])
        self.assertEqual(
            response["parameters"],
            {
                "max_tokens": -1,
                "temperature": 0.7,
                "top_p": 0.88,
                "top_k": 64,
                "repeat_penalty": 1.08,
            },
        )
        self.assertEqual(requested_urls[0], "http://127.0.0.1:11435/props?model=test+model")

    def test_model_defaults_support_nested_router_params(self) -> None:
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self) -> bytes:
                return json.dumps(
                    {
                        "default_generation_settings": {
                            "params": {
                                "n_predict": 2048,
                                "temp": 0.45,
                                "top_p": 0.91,
                                "top_k": 32,
                                "repeat_penalty": 1.12,
                            },
                            "n_ctx": 8192,
                        }
                    }
                ).encode("utf-8")

        with patch("linux_troubleshoot_agent.web.urllib.request.urlopen", lambda *args, **kwargs: FakeResponse()):
            response = handle_model_defaults(
                {
                    "base_url": "http://127.0.0.1:11435/v1",
                    "model": "router-model",
                }
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["parameters"]["max_tokens"], 2048)
        self.assertEqual(response["parameters"]["temperature"], 0.45)


class StaticConfigurationTests(unittest.TestCase):
    def test_docker_defaults_bind_privileged_gui_to_localhost(self) -> None:
        compose = Path("compose.yaml").read_text(encoding="utf-8")
        dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

        self.assertIn("- 127.0.0.1", compose)
        self.assertNotIn("- 0.0.0.0", compose)
        self.assertIn('"--host", "127.0.0.1"', dockerfile)
        self.assertNotIn('"--host", "0.0.0.0"', dockerfile)

    def test_stream_control_events_clear_draft_without_finalizing_live_stream(self) -> None:
        html = Path("src/linux_troubleshoot_agent/web_assets/index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn("function clearLiveDraft(live)", html)
        self.assertIn("clearLiveDraft(live);\n        renderEvent(event);", html)
        self.assertNotIn("removeLiveIfOnlyStatus(live);\n        renderEvent(event);", html)
        self.assertIn("async function runAction(action, confirmed)", html)
        self.assertIn("confirmed !== undefined", html)

    def test_model_selection_fetches_llamacpp_parameter_defaults(self) -> None:
        html = Path("src/linux_troubleshoot_agent/web_assets/index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn('post("/api/model-defaults"', html)
        self.assertIn("function applyParameterDefaults(defaults)", html)
        self.assertIn("loadModelDefaults(id);", html)
        self.assertIn('min="-1"', html)


if __name__ == "__main__":
    unittest.main()
