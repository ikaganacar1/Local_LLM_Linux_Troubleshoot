from __future__ import annotations

import json
import subprocess
import sys
import unittest
from types import SimpleNamespace

from linux_troubleshoot_agent.safety import SafetyDecision, classify_command
from linux_troubleshoot_agent.shell import run_command
from linux_troubleshoot_agent.storage import PermissionSettings
from linux_troubleshoot_agent.web import (
    SESSIONS,
    WebSession,
    _permission_allows_command,
    handle_approval,
)


class SafetyRegressionTests(unittest.TestCase):
    def test_shell_substitution_requires_approval(self) -> None:
        result = classify_command("ls $(touch ~/.pwned)")
        self.assertEqual(result.decision, SafetyDecision.NEEDS_APPROVAL)

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


if __name__ == "__main__":
    unittest.main()
