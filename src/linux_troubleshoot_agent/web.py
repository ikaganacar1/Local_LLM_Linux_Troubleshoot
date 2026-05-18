from __future__ import annotations

import argparse
import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any

from .agent import Agent
from .config import Config
from .llama_cpp_client import LlamaCppError
from .safety import SafetyDecision, classify_command
from .shell import CommandResult, run_command
from .storage import PermissionSettings, load_memory, load_settings, remember_scan, save_settings
from .system_scan import (
    apply_home_organization,
    detect_package_manager,
    plan_home_organization,
    run_system_scan,
    update_apply_command,
    update_check_command,
)


@dataclass
class WebSession:
    agent: Agent
    pending_command: str | None = None
    pending_reason: str | None = None
    pending_organize_plan: dict[str, Any] | None = None


SESSIONS: dict[str, WebSession] = {}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Browser GUI for the Linux troubleshooting agent.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=28765)
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Linux Troubleshooting Agent GUI: http://{args.host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        return 0
    return 0


class Handler(BaseHTTPRequestHandler):
    server_version = "LinuxTroubleshootAgent/0.1"

    def do_HEAD(self) -> None:
        if self.path in {"/", "/index.html"}:
            data = _asset("index.html")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self._send_bytes(_asset("index.html"), "text/html; charset=utf-8")
            return
        if self.path == "/api/state":
            self._send_json(
                {
                    "ok": True,
                    "settings": _settings_dict(load_settings()),
                    "memory": load_memory(),
                }
            )
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        try:
            payload = self._read_json()
            if self.path == "/api/message":
                self._send_json(handle_message(payload))
                return
            if self.path == "/api/approve":
                self._send_json(handle_approval(payload))
                return
            if self.path == "/api/settings":
                self._send_json(handle_settings(payload))
                return
            if self.path == "/api/scan":
                self._send_json(handle_scan(payload))
                return
            if self.path == "/api/action":
                self._send_json(handle_action(payload))
                return
            if self.path == "/api/models":
                self._send_json(handle_models(payload))
                return
            self.send_error(HTTPStatus.NOT_FOUND)
        except LlamaCppError as exc:
            self._send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_GATEWAY)
        except Exception as exc:  # Keep local UI errors visible instead of dropping the request.
            self._send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        size = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(size).decode("utf-8")
        return json.loads(raw or "{}")

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, data: bytes, content_type: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def handle_message(payload: dict[str, Any]) -> dict[str, Any]:
    session_id, session = _get_or_create_session(payload)
    message = str(payload.get("message", "")).strip()
    if not message:
        return {"ok": False, "error": "Message is empty."}

    session.pending_command = None
    session.pending_reason = None
    session.agent.add_user_message(message)
    events = _continue_session(session)
    return {"ok": True, "session_id": session_id, "events": events}


def handle_models(payload: dict[str, Any]) -> dict[str, Any]:
    env_config = Config.from_env()
    base_url = str(payload.get("base_url") or env_config.base_url).strip().rstrip("/")
    api_key = str(payload.get("api_key") or "").strip() or env_config.api_key
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(f"{base_url}/models", headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        return {"ok": False, "error": f"Could not reach llama.cpp models endpoint: {exc}"}
    except json.JSONDecodeError:
        return {"ok": False, "error": "llama.cpp returned invalid JSON for models."}

    models = []
    for item in body.get("data", []):
        if isinstance(item, dict) and item.get("id"):
            models.append({"id": str(item["id"]), "owned_by": str(item.get("owned_by", ""))})
    return {"ok": True, "models": models}


def handle_approval(payload: dict[str, Any]) -> dict[str, Any]:
    session_id = str(payload.get("session_id", ""))
    session = SESSIONS.get(session_id)
    if session is None:
        return {"ok": False, "error": "Unknown session."}
    if not session.pending_command:
        return {"ok": False, "error": "No command is waiting for approval."}

    command = session.pending_command
    approved = bool(payload.get("approved"))
    session.pending_command = None
    session.pending_reason = None

    if not approved:
        session.agent.record_controller_note(f"User declined command `{command}`.")
        return {"ok": True, "session_id": session_id, "events": [{"type": "notice", "content": "Skipped."}]}

    safety = classify_command(command)
    if safety.decision == SafetyDecision.FORBIDDEN:
        note = f"Blocked forbidden command `{command}`: {safety.reason}"
        session.agent.record_controller_note(note)
        return {"ok": True, "session_id": session_id, "events": [{"type": "blocked", "content": note}]}

    result = run_command(command, session.agent.config.timeout_seconds)
    session.agent.record_command_result(result)
    events = [_command_event(result)]
    events.extend(_continue_session(session))
    return {"ok": True, "session_id": session_id, "events": events}


def handle_settings(payload: dict[str, Any]) -> dict[str, Any]:
    settings_payload = payload.get("settings", payload)
    settings = PermissionSettings(
        auto_run_readonly_scan=bool(settings_payload.get("auto_run_readonly_scan", True)),
        allow_package_updates=bool(settings_payload.get("allow_package_updates", False)),
        allow_service_changes=bool(settings_payload.get("allow_service_changes", False)),
        allow_personal_folder_organize=bool(settings_payload.get("allow_personal_folder_organize", False)),
        require_confirmation_for_modifying=bool(settings_payload.get("require_confirmation_for_modifying", True)),
    )
    save_settings(settings)
    return {"ok": True, "settings": _settings_dict(settings), "memory": load_memory()}


def handle_scan(payload: dict[str, Any]) -> dict[str, Any]:
    session_id, session = _get_or_create_session(payload)
    settings = load_settings()
    if not settings.auto_run_readonly_scan:
        return {
            "ok": False,
            "error": "Read-only scan permission is disabled in settings.",
            "session_id": session_id,
        }

    scan = run_system_scan(session.agent.config.timeout_seconds)
    memory = remember_scan(scan["summary"])
    events = [
        {
            "type": "scan_summary",
            "summary": scan["summary"],
            "results": scan["results"],
        }
    ]

    session.agent.add_user_message(
        "Analyze this automatic Linux system scan. Keep the answer short, rank likely issues, "
        "and do not suggest modifying commands unless permissions are enabled.\n\n"
        + json.dumps(scan["summary"], indent=2)
    )
    try:
        events.extend(_continue_session(session))
    except LlamaCppError as exc:
        events.append({"type": "notice", "content": f"Scan completed. Model summary skipped: {exc}"})

    return {"ok": True, "session_id": session_id, "events": events, "memory": memory}


def handle_action(payload: dict[str, Any]) -> dict[str, Any]:
    session_id, session = _get_or_create_session(payload)
    action = str(payload.get("action", "")).strip()
    settings = load_settings()

    if action == "check_updates":
        package_manager = detect_package_manager()
        command = update_check_command(package_manager)
        if not command:
            return {"ok": False, "session_id": session_id, "error": "No supported package manager detected."}
        result = run_command(command, session.agent.config.timeout_seconds)
        return {
            "ok": True,
            "session_id": session_id,
            "events": [
                {"type": "notice", "content": f"Detected package manager: {package_manager}"},
                _command_event(result),
            ],
        }

    if action == "apply_updates":
        if not settings.allow_package_updates:
            return {
                "ok": False,
                "session_id": session_id,
                "error": "Package update permission is disabled in settings.",
            }
        package_manager = detect_package_manager()
        command = update_apply_command(package_manager)
        if not command:
            return {"ok": False, "session_id": session_id, "error": "No supported package manager detected."}
        if settings.require_confirmation_for_modifying and not payload.get("confirmed"):
            return {
                "ok": True,
                "session_id": session_id,
                "events": [
                    {
                        "type": "action_confirmation",
                        "action": "apply_updates",
                        "reason": f"This will run system package updates through {package_manager}.",
                        "command": command,
                    }
                ],
            }
        result = run_command(command, 1800)
        return {"ok": True, "session_id": session_id, "events": [_command_event(result)]}

    if action == "organize_preview":
        plan = plan_home_organization()
        session.pending_organize_plan = plan
        return {"ok": True, "session_id": session_id, "events": [{"type": "organize_plan", "plan": plan}]}

    if action == "organize_apply":
        if not settings.allow_personal_folder_organize:
            return {
                "ok": False,
                "session_id": session_id,
                "error": "Personal folder organization permission is disabled in settings.",
            }
        plan = session.pending_organize_plan or plan_home_organization()
        if settings.require_confirmation_for_modifying and not payload.get("confirmed"):
            return {
                "ok": True,
                "session_id": session_id,
                "events": [
                    {
                        "type": "action_confirmation",
                        "action": "organize_apply",
                        "reason": f"This will move {plan.get('move_count', 0)} files into ~/Organized by type.",
                        "command": "internal file organization action",
                    }
                ],
            }
        result = apply_home_organization(plan)
        session.pending_organize_plan = None
        return {"ok": True, "session_id": session_id, "events": [{"type": "organize_result", "result": result}]}

    return {"ok": False, "session_id": session_id, "error": f"Unknown action: {action}"}


def _get_or_create_session(payload: dict[str, Any]) -> tuple[str, WebSession]:
    session_id = str(payload.get("session_id") or "")
    if session_id and session_id in SESSIONS:
        return session_id, SESSIONS[session_id]

    env_config = Config.from_env()
    base_url = str(payload.get("base_url") or env_config.base_url).strip()
    model = str(payload.get("model") or env_config.model).strip()
    api_key = str(payload.get("api_key") or "").strip() or env_config.api_key

    config = Config(
        base_url=base_url,
        model=model,
        api_key=api_key,
        system_prompt_path=env_config.system_prompt_path,
        timeout_seconds=env_config.timeout_seconds,
        max_steps=env_config.max_steps,
    )
    session_id = secrets.token_urlsafe(16)
    SESSIONS[session_id] = WebSession(agent=Agent.create(config))
    return session_id, SESSIONS[session_id]


def _continue_session(session: WebSession) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    settings = load_settings()
    for _ in range(session.agent.config.max_steps):
        action = session.agent.next_action()
        action_type = action.get("type")

        if action_type == "message":
            events.append({"type": "message", "content": str(action.get("content", "")).strip()})
            return events

        if action_type not in {"command", "approval"}:
            events.append({"type": "message", "content": str(action)})
            return events

        reason = str(action.get("reason", "")).strip()
        command = str(action.get("command", "")).strip()
        if not command:
            events.append({"type": "notice", "content": "The model requested an empty command."})
            return events

        events.append({"type": "proposed_command", "reason": reason, "command": command})

        if action_type == "approval":
            safety = classify_command(command)
            if safety.decision == SafetyDecision.FORBIDDEN:
                note = f"Blocked forbidden command `{command}`: {safety.reason}"
                session.agent.record_controller_note(note)
                events.append({"type": "blocked", "content": note})
                continue
            if _permission_allows_command(command, settings) and not settings.require_confirmation_for_modifying:
                result = run_command(command, session.agent.config.timeout_seconds)
                session.agent.record_command_result(result)
                events.append(_command_event(result))
                continue
            session.pending_command = command
            session.pending_reason = reason
            events.append({"type": "approval_required", "reason": reason, "command": command})
            return events

        safety = classify_command(command)
        if safety.decision == SafetyDecision.FORBIDDEN:
            note = f"Blocked forbidden command `{command}`: {safety.reason}"
            session.agent.record_controller_note(note)
            events.append({"type": "blocked", "content": note})
            continue

        if safety.decision == SafetyDecision.NEEDS_APPROVAL:
            if _permission_allows_command(command, settings) and not settings.require_confirmation_for_modifying:
                result = run_command(command, session.agent.config.timeout_seconds)
                session.agent.record_command_result(result)
                events.append(_command_event(result))
                continue
            session.pending_command = command
            session.pending_reason = safety.reason
            events.append({"type": "approval_required", "reason": safety.reason, "command": command})
            return events

        result = run_command(command, session.agent.config.timeout_seconds)
        session.agent.record_command_result(result)
        events.append(_command_event(result))

    events.append({"type": "notice", "content": "Stopped after reaching the per-turn step limit."})
    return events


def _command_event(result: CommandResult) -> dict[str, Any]:
    return {
        "type": "command_result",
        "command": result.command,
        "exit_code": result.exit_code,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-4000:],
        "timed_out": result.timed_out,
    }


def _settings_dict(settings: PermissionSettings) -> dict[str, bool]:
    return {
        "auto_run_readonly_scan": settings.auto_run_readonly_scan,
        "allow_package_updates": settings.allow_package_updates,
        "allow_service_changes": settings.allow_service_changes,
        "allow_personal_folder_organize": settings.allow_personal_folder_organize,
        "require_confirmation_for_modifying": settings.require_confirmation_for_modifying,
    }


def _permission_allows_command(command: str, settings: PermissionSettings) -> bool:
    normalized = command.strip()
    package_update_commands = (
        "sudo pacman -Syu --noconfirm",
        "sudo apt update && sudo apt upgrade -y",
        "sudo dnf upgrade -y",
        "sudo zypper update -y",
        "sudo apk update && sudo apk upgrade",
    )
    if settings.allow_package_updates and normalized in package_update_commands:
        return True
    if settings.allow_service_changes and normalized.startswith(("systemctl ", "sudo systemctl ", "service ", "sudo service ")):
        return True
    return False


def _asset(name: str) -> bytes:
    return files("linux_troubleshoot_agent").joinpath("web_assets", name).read_bytes()


if __name__ == "__main__":
    raise SystemExit(main())
