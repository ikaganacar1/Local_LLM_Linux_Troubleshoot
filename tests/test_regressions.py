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
from linux_troubleshoot_agent.storage import PermissionSettings, auth_token, load_memory, save_settings
from linux_troubleshoot_agent.system_scan import recommend_repairs, summarize_scan, update_check_command
from linux_troubleshoot_agent.web import (
    Handler,
    PASSWORD_SESSIONS,
    SESSIONS,
    WebSession,
    _index_asset,
    _extract_context_size,
    _optional_float_payload,
    _optional_int_payload,
    _parse_issue_review,
    _permission_allows_command,
    _service_change_allowed,
    handle_approval,
    handle_action,
    handle_export,
    handle_issue_review,
    handle_login,
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

    def test_root_rm_flag_orderings_are_forbidden(self) -> None:
        for command in ("rm -fr /", "rm -f -r /", "sudo rm -rf /"):
            with self.subTest(command=command):
                result = classify_command(command)
                self.assertEqual(result.decision, SafetyDecision.FORBIDDEN)

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

    def test_service_auto_permission_is_limited_to_service_changes(self) -> None:
        settings = PermissionSettings(
            allow_service_changes=True,
            require_confirmation_for_modifying=False,
        )

        self.assertTrue(_permission_allows_command("systemctl restart sshd.service", settings))
        self.assertTrue(_permission_allows_command("sudo systemctl restart sshd", settings))
        self.assertFalse(_permission_allows_command("systemctl reboot", settings))
        self.assertFalse(_permission_allows_command("sudo systemctl poweroff", settings))
        self.assertFalse(_permission_allows_command("systemctl isolate rescue.target", settings))
        self.assertFalse(_service_change_allowed("systemctl restart default.target"))

    def test_timeout_output_is_json_serializable(self) -> None:
        result = run_command("printf hi; sleep 2", 1)

        self.assertTrue(result.timed_out)
        self.assertIsInstance(result.stdout, str)
        self.assertIsInstance(result.stderr, str)
        json.dumps({"stdout": result.stdout, "stderr": result.stderr})

    def test_command_runner_does_not_execute_shell_substitution(self) -> None:
        marker = Path(tempfile.gettempdir()) / f"lta-shell-{os.getpid()}"
        if marker.exists():
            marker.unlink()

        result = run_command(f"ls $(touch {marker})", 5)

        self.assertNotEqual(result.exit_code, 0)
        self.assertFalse(marker.exists())

    def test_missing_executable_is_command_failure_not_crash(self) -> None:
        result = run_command("definitely-not-installed-lta-command --version", 5)

        self.assertEqual(result.exit_code, 127)
        self.assertIn("definitely-not-installed-lta-command", result.stderr)

    def test_redirection_is_rejected_by_command_runner(self) -> None:
        result = run_command("echo value > /tmp/lta-redirect-test", 5)

        self.assertEqual(result.exit_code, 127)
        self.assertIn("redirection", result.stderr.lower())

    def test_quoted_punctuation_remains_command_argument(self) -> None:
        result = run_command("sed -n '1p;1p' /etc/os-release", 5)

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.stdout.strip())

    def test_quoted_alpine_update_less_than_argument_is_not_redirection(self) -> None:
        command = update_check_command("apk")
        self.assertEqual(command, "apk version -l '<'")

        result = run_command(command, 5)
        self.assertNotIn("redirection", result.stderr.lower())

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
        self._old_ui_password = os.environ.get("LTA_UI_PASSWORD")
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        os.environ["LTA_DATA_DIR"] = str(root / "data")
        os.environ["LTA_HOST_HOME"] = str(root / "home")
        Path(os.environ["LTA_HOST_HOME"]).mkdir()
        SESSIONS.clear()
        PASSWORD_SESSIONS.clear()

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
        if self._old_ui_password is None:
            os.environ.pop("LTA_UI_PASSWORD", None)
        else:
            os.environ["LTA_UI_PASSWORD"] = self._old_ui_password
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
        self.assertEqual(response["context_size"], 8192)

    def test_context_size_can_be_extracted_from_nested_props(self) -> None:
        self.assertEqual(
            _extract_context_size(
                {"default_generation_settings": {"params": {"n_ctx": 200192}}}
            ),
            200192,
        )
        self.assertEqual(_extract_context_size({"n_ctx": 32768}), 32768)

    def test_workflow_action_returns_structured_scan_and_audit(self) -> None:
        with (
            patch("linux_troubleshoot_agent.web.run_workflow_scan") as scan,
            patch("linux_troubleshoot_agent.web._continue_session") as continued,
        ):
            scan.return_value = {
                "summary": {
                    "workflow": "network",
                    "package_manager": "apt",
                    "issues": [{"severity": "medium", "title": "Network issue"}],
                    "repair_plans": [],
                },
                "results": {"network": {"stdout": "ok", "stderr": "", "exit_code": 0}},
            }
            continued.return_value = [{"type": "message", "content": "Network summary"}]
            response = handle_action({"session_id": "workflow-test", "action": "workflow_network"})

        self.assertTrue(response["ok"])
        self.assertEqual(response["events"][0]["type"], "workflow_summary")
        self.assertEqual(response["events"][1]["content"], "Network summary")
        self.assertEqual(load_memory()["audit"][-1]["kind"], "workflow")

    def test_blank_llm_parameters_mean_server_defaults(self) -> None:
        self.assertIsNone(_optional_int_payload({"max_tokens": None}, "max_tokens", 4096))
        self.assertIsNone(_optional_float_payload({"temperature": ""}, "temperature", 0.2))

    def test_packages_workflow_reports_updates_from_workflow_key(self) -> None:
        summary = summarize_scan(
            {
                "updates_apt": {
                    "stdout": "Listing...\nvim/now 2:9.1 amd64 [upgradable]\n",
                    "stderr": "",
                    "exit_code": 0,
                }
            },
            "apt",
        )

        titles = [issue["title"] for issue in summary["issues"]]
        self.assertIn("Package updates available", titles)
        self.assertEqual(summary["update_count"], 1)

    def test_default_memory_is_not_shared_between_data_dirs(self) -> None:
        first = Path(self._tmp.name) / "first-memory"
        second = Path(self._tmp.name) / "second-memory"

        os.environ["LTA_DATA_DIR"] = str(first)
        memory = load_memory()
        memory["facts"]["os_name"] = "stale"
        memory["audit"].append({"kind": "stale"})

        os.environ["LTA_DATA_DIR"] = str(second)
        fresh = load_memory()

        self.assertEqual(fresh["facts"], {})
        self.assertEqual(fresh["audit"], [])

    def test_df_boot_mountpoint_is_skipped_and_failed_bullet_is_profiled(self) -> None:
        summary = summarize_scan(
            {
                "disk_space": {
                    "stdout": (
                        "Filesystem Type Size Used Avail Use% Mounted on\n"
                        "/dev/sda1 ext4 1G 950M 50M 95% /boot\n"
                        "/dev/sda2 ext4 10G 9.5G 500M 95% /\n"
                    ),
                    "stderr": "",
                    "exit_code": 0,
                },
                "failed_services": {
                    "stdout": "● wol@enp11s0.service loaded failed failed Wake-on-LAN\n",
                    "stderr": "",
                    "exit_code": 0,
                },
            },
            "apt",
        )

        disk_issues = [issue for issue in summary["issues"] if issue["title"] == "Filesystem nearly full"]
        self.assertEqual(len(disk_issues), 1)
        self.assertNotIn("/boot", disk_issues[0]["detail"])
        self.assertIn("/", disk_issues[0]["detail"])
        self.assertIn("wol@enp11s0.service", summary["failed_services"])
        self.assertTrue(summary["repair_plans"])
        self.assertIn("wol@enp11s0.service", "\n".join(summary["repair_plans"][0]["commands"]))

    def test_repair_plans_include_distro_update_command(self) -> None:
        plans = recommend_repairs(
            [{"severity": "medium", "title": "Package updates available"}],
            {},
            "apt",
        )

        commands = "\n".join(plans[0]["commands"])
        self.assertIn("apt list --upgradable", commands)
        self.assertIn("sudo apt update && sudo apt upgrade -y", commands)

    def test_export_returns_profile_or_audit_json(self) -> None:
        load_memory()
        first = handle_export({"type": "profile"})
        second = handle_export({"type": "audit"})

        self.assertTrue(first["ok"])
        self.assertIn("facts", first["content"])
        self.assertTrue(second["ok"])
        self.assertIn("audit", second["content"])
        self.assertGreaterEqual(len(load_memory()["audit"]), 2)

    def test_optional_ui_password_issues_session_token(self) -> None:
        os.environ["LTA_UI_PASSWORD"] = "secret"

        failed = handle_login({"password": "wrong"})
        passed = handle_login({"password": "secret"})

        self.assertFalse(failed["ok"])
        self.assertTrue(passed["ok"])
        self.assertIn(passed["login_token"], PASSWORD_SESSIONS)

    def test_issue_review_parser_maps_statuses_to_existing_issue_tasks(self) -> None:
        tasks = _parse_issue_review(
            '{"tasks":[{"title":"Package updates available","status":"probably_fixed","reason":"apt upgrade exited 0"}]}',
            [{"title": "Package updates available", "next_step": "Run updates."}],
        )

        self.assertEqual(tasks[0]["status"], "probably_fixed")
        self.assertEqual(tasks[0]["reason"], "apt upgrade exited 0")

    def test_issue_review_handler_uses_llm_task_statuses(self) -> None:
        class FakeClient:
            def __init__(self, **kwargs):
                pass

            def chat(self, *args, **kwargs):
                return '{"tasks":[{"title":"wol failed","status":"still_open","reason":"No service evidence changed"}]}'

        with patch("linux_troubleshoot_agent.web.LlamaCppClient", FakeClient):
            response = handle_issue_review(
                {
                    "issues": [{"title": "wol failed", "detail": "service failed"}],
                    "evidence": {"command": "true"},
                }
            )

        self.assertTrue(response["ok"])
        self.assertEqual(response["tasks"][0]["status"], "still_open")


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
        self.assertIn("context_size", html)
        self.assertIn("Remaining Context", html)
        self.assertIn("function updateTopIndicators()", html)

    def test_index_embeds_local_auth_token_placeholder_replacement(self) -> None:
        html = _index_asset().decode("utf-8")

        self.assertIn(auth_token(), html)
        self.assertNotIn("__LTA_AUTH_TOKEN__", html)

    def test_post_auth_checks_require_local_token_and_trusted_origin(self) -> None:
        handler = object.__new__(Handler)
        token = auth_token()
        handler.headers = {"X-LTA-Token": token, "Host": "127.0.0.1:28765"}
        self.assertTrue(Handler._authorized(handler))
        self.assertTrue(Handler._trusted_origin(handler))

        handler.headers = {
            "X-LTA-Token": "wrong",
            "Host": "127.0.0.1:28765",
            "Origin": "http://evil.local",
        }
        self.assertFalse(Handler._authorized(handler))
        self.assertFalse(Handler._trusted_origin(handler))

    def test_ui_has_workflow_issue_dashboard_and_approval_plan(self) -> None:
        html = Path("src/linux_troubleshoot_agent/web_assets/index.html").read_text(
            encoding="utf-8"
        )

        self.assertIn('id="issueDashboard"', html)
        self.assertIn('data-workflow="network"', html)
        self.assertIn("function renderPlan(plan)", html)
        self.assertIn("function renderRepairPlans(plans)", html)
        self.assertIn('id="exportAudit"', html)
        self.assertIn('post("/api/export"', html)
        self.assertIn('id="loginDialog"', html)
        self.assertIn('post("/api/login"', html)
        self.assertIn('id="confirmDialog"', html)
        self.assertIn("function resolveConfirmation(approved)", html)
        self.assertIn("confirmCommandPreview", html)
        self.assertIn("runWorkflow(button.dataset.workflow)", html)
        self.assertIn('event.key !== "Enter"', html)
        self.assertIn("form.requestSubmit()", html)
        self.assertIn("function splitThinkingBlocks(text)", html)
        self.assertIn("thinking-details", html)
        self.assertIn("live-thinking", html)
        self.assertIn("Thinking tokens (~", html)
        self.assertIn("live.thinkingPre.textContent", html)
        self.assertIn("No reasoning tokens received yet", html)
        self.assertIn("Waiting for reasoning tokens from llama.cpp", html)
        self.assertIn("Issue Tasks", html)
        self.assertIn("function reviewIssuesAfterChange(evidence)", html)
        self.assertIn('post("/api/review-issues"', html)
        self.assertIn("LLM is reviewing issue tasks", html)
        self.assertNotIn("function refreshIssuesAfterChange(label)", html)
        self.assertNotIn("basePayload({ analyze: false })", html)

    def test_streaming_client_preserves_reasoning_deltas(self) -> None:
        source = Path("src/linux_troubleshoot_agent/llama_cpp_client.py").read_text(
            encoding="utf-8"
        )

        self.assertIn('delta.get("reasoning_content")', source)
        self.assertIn('yield f"<think>{reasoning}</think>"', source)


if __name__ == "__main__":
    unittest.main()
