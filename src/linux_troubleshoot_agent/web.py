from __future__ import annotations

import argparse
import hmac
import json
import os
import secrets
import shlex
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from typing import Any

from .agent import Agent
from .config import Config
from .llama_cpp_client import LlamaCppError
from .llama_cpp_client import LlamaCppClient
from .safety import SafetyDecision, classify_command
from .shell import CommandResult, run_command
from .storage import (
    PermissionSettings,
    append_audit,
    auth_token,
    load_memory,
    load_settings,
    remember_scan,
    save_settings,
)
from .system_scan import (
    WORKFLOWS,
    apply_home_organization,
    detect_package_manager,
    plan_home_organization,
    run_workflow_scan,
    run_system_scan,
    update_apply_command,
    update_check_command,
)


@dataclass
class WebSession:
    agent: Agent
    pending_command: str | None = None
    pending_reason: str | None = None
    pending_plan: dict[str, Any] | None = None
    pending_organize_plan: dict[str, Any] | None = None


SESSIONS: dict[str, WebSession] = {}
PASSWORD_SESSIONS: set[str] = set()


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
            data = _index_asset()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_GET(self) -> None:
        if self.path in {"/", "/index.html"}:
            self._send_bytes(_index_asset(), "text/html; charset=utf-8")
            return
        if self.path == "/api/state":
            if _password_required() and not self._password_authorized():
                self._send_json({"ok": False, "password_required": True, "error": "UI password required."}, HTTPStatus.UNAUTHORIZED)
                return
            self._send_json(
                {
                    "ok": True,
                    "password_required": _password_required(),
                    "settings": _settings_dict(load_settings()),
                    "memory": load_memory(),
                }
            )
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        try:
            if not self._trusted_origin() or not self._authorized():
                self._send_json({"ok": False, "error": "Unauthorized local request."}, HTTPStatus.FORBIDDEN)
                return
            payload = self._read_json()
            if self.path == "/api/login":
                self._send_json(handle_login(payload))
                return
            if _password_required() and not self._password_authorized():
                self._send_json({"ok": False, "password_required": True, "error": "UI password required."}, HTTPStatus.UNAUTHORIZED)
                return
            if self.path == "/api/message-stream":
                self._send_message_stream(payload)
                return
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
            if self.path == "/api/model-defaults":
                self._send_json(handle_model_defaults(payload))
                return
            if self.path == "/api/title":
                self._send_json(handle_title(payload))
                return
            if self.path == "/api/export":
                self._send_json(handle_export(payload))
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

    def _send_message_stream(self, payload: dict[str, Any]) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()

        def emit(event: dict[str, Any]) -> None:
            self.wfile.write((json.dumps(event) + "\n").encode("utf-8"))
            self.wfile.flush()

        try:
            handle_message_stream(payload, emit)
        except LlamaCppError as exc:
            emit({"type": "error", "content": str(exc)})
        except Exception as exc:
            emit({"type": "error", "content": str(exc)})

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-LTA-Token", "")
        return hmac.compare_digest(supplied, auth_token())

    def _password_authorized(self) -> bool:
        if not _password_required():
            return True
        supplied = self.headers.get("X-LTA-Login", "")
        return bool(supplied and supplied in PASSWORD_SESSIONS)

    def _trusted_origin(self) -> bool:
        origin = self.headers.get("Origin") or self.headers.get("Referer")
        if not origin:
            return True
        parsed = urllib.parse.urlparse(origin)
        return parsed.netloc == self.headers.get("Host")


def handle_message(payload: dict[str, Any]) -> dict[str, Any]:
    session_id, session = _get_or_create_session(payload)
    message = str(payload.get("message", "")).strip()
    if not message:
        return {"ok": False, "error": "Message is empty."}

    session.pending_command = None
    session.pending_reason = None
    session.pending_plan = None
    session.agent.add_user_message(message)
    events = _continue_session(session)
    return {"ok": True, "session_id": session_id, "events": events}


def handle_message_stream(payload: dict[str, Any], emit) -> None:
    session_id, session = _get_or_create_session(payload)
    message = str(payload.get("message", "")).strip()
    emit({"type": "session", "session_id": session_id})
    if not message:
        emit({"type": "error", "content": "Message is empty."})
        return

    session.pending_command = None
    session.pending_reason = None
    session.pending_plan = None
    session.agent.add_user_message(message)
    _continue_session_stream(session, emit)


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


def handle_model_defaults(payload: dict[str, Any]) -> dict[str, Any]:
    env_config = Config.from_env()
    base_url = str(payload.get("base_url") or env_config.base_url).strip().rstrip("/")
    model = str(payload.get("model") or env_config.model).strip()
    api_key = str(payload.get("api_key") or "").strip() or env_config.api_key
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    errors: list[str] = []
    for url in _props_urls(base_url, model):
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                body = json.loads(response.read().decode("utf-8"))
        except TimeoutError:
            errors.append(f"{url} timed out")
            continue
        except urllib.error.URLError as exc:
            errors.append(str(exc))
            continue
        except json.JSONDecodeError:
            return {"ok": False, "error": "llama.cpp returned invalid JSON for model defaults."}

        parameters = _extract_generation_parameters(body)
        if parameters:
            return {
                "ok": True,
                "model": model,
                "parameters": parameters,
                "source": "/props default_generation_settings",
            }
        errors.append("No default_generation_settings found.")

    detail = "; ".join(errors[-2:]) if errors else "No response from llama.cpp."
    return {"ok": False, "error": f"Could not load llama.cpp defaults: {detail}"}


def _props_urls(base_url: str, model: str) -> list[str]:
    trimmed = base_url.rstrip("/")
    roots = []
    if trimmed.endswith("/v1"):
        roots.append(trimmed[: -len("/v1")])
    roots.append(trimmed)

    seen: set[str] = set()
    urls: list[str] = []
    query = urllib.parse.urlencode({"model": model}) if model else ""
    for root in roots:
        url = f"{root}/props"
        if query:
            url = f"{url}?{query}"
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _extract_generation_parameters(body: Any) -> dict[str, int | float]:
    if not isinstance(body, dict):
        return {}
    settings = body.get("default_generation_settings") or body.get("generation_settings")
    if not isinstance(settings, dict):
        slots = body.get("slots")
        if isinstance(slots, list) and slots and isinstance(slots[0], dict):
            slot_params = slots[0].get("params")
            if isinstance(slot_params, dict):
                settings = slot_params
    if not isinstance(settings, dict):
        return {}
    nested_params = settings.get("params")
    if isinstance(nested_params, dict):
        settings = {**nested_params, **settings}

    aliases = {
        "max_tokens": ("max_tokens", "n_predict"),
        "temperature": ("temperature", "temp"),
        "top_p": ("top_p",),
        "top_k": ("top_k",),
        "repeat_penalty": ("repeat_penalty",),
    }
    integer_fields = {"max_tokens", "top_k"}
    parameters: dict[str, int | float] = {}
    for target, names in aliases.items():
        value = next((settings[name] for name in names if name in settings), None)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if target in integer_fields:
            parameters[target] = int(value)
        else:
            parameters[target] = round(float(value), 4)
    return parameters


def handle_title(payload: dict[str, Any]) -> dict[str, Any]:
    env_config = Config.from_env()
    base_url = str(payload.get("base_url") or env_config.base_url).strip()
    model = str(payload.get("model") or env_config.model).strip()
    api_key = str(payload.get("api_key") or "").strip() or env_config.api_key
    user_text = str(payload.get("message") or "").strip()
    if not user_text:
        return {"ok": False, "error": "Message is empty."}

    client = LlamaCppClient(base_url=base_url, model=model, api_key=api_key)
    prompt = (
        "Name this troubleshooting chat in 2 to 5 words. "
        "Return only the title, no quotes, no punctuation at the end.\n\n"
        + user_text[:800]
    )
    try:
        title = client.chat(
            [{"role": "user", "content": prompt}],
            max_tokens=32,
            temperature=0.2,
            top_p=0.9,
            top_k=40,
            repeat_penalty=1.05,
        ).strip()
    except LlamaCppError as exc:
        return {"ok": False, "error": str(exc)}
    title = " ".join(title.replace("\n", " ").split()).strip(" \"'`")
    return {"ok": True, "title": title[:64] or "Troubleshooting Chat"}


def handle_login(payload: dict[str, Any]) -> dict[str, Any]:
    expected = _ui_password()
    if not expected:
        return {"ok": True, "password_required": False, "login_token": ""}
    supplied = str(payload.get("password") or "")
    if not hmac.compare_digest(supplied, expected):
        return {"ok": False, "password_required": True, "error": "Wrong password."}
    login_token = secrets.token_urlsafe(32)
    PASSWORD_SESSIONS.add(login_token)
    return {"ok": True, "password_required": True, "login_token": login_token}


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
    plan = session.pending_plan
    session.pending_plan = None

    if not approved:
        session.agent.record_controller_note(f"User declined command `{command}`.")
        append_audit({"kind": "command", "action": "declined", "command": command, "plan": plan})
        return {"ok": True, "session_id": session_id, "events": [{"type": "notice", "content": "Skipped."}]}

    safety = classify_command(command)
    if safety.decision == SafetyDecision.FORBIDDEN:
        note = f"Blocked forbidden command `{command}`: {safety.reason}"
        session.agent.record_controller_note(note)
        return {"ok": True, "session_id": session_id, "events": [{"type": "blocked", "content": note}]}

    result = _execute_command(session, command, session.agent.config.timeout_seconds, "user_approved", plan)
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
    append_audit({"kind": "scan", "action": "run", "issue_count": len(scan["summary"].get("issues", []))})
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
        result = _execute_command(session, command, session.agent.config.timeout_seconds, "workflow")
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
        if settings.require_confirmation_for_modifying and payload.get("confirmed") is not True:
            if payload.get("confirmed") is False:
                append_audit({"kind": "action", "action": "declined", "name": "apply_updates", "command": command})
                return _declined_action_response(session_id, "Package update skipped.")
            reason = f"This will run system package updates through {package_manager}."
            return {
                "ok": True,
                "session_id": session_id,
                "events": [
                    {
                        "type": "action_confirmation",
                        "action": "apply_updates",
                        "reason": reason,
                        "command": command,
                        "plan": _action_plan("apply_updates", command, reason),
                    }
                ],
            }
        result = _execute_command(session, command, 1800, "user_approved", _action_plan("apply_updates", command, "Package update action"))
        return {"ok": True, "session_id": session_id, "events": [_command_event(result)]}

    if action.startswith("workflow_"):
        workflow = action.removeprefix("workflow_")
        if workflow not in WORKFLOWS:
            return {"ok": False, "session_id": session_id, "error": f"Unknown workflow: {workflow}"}
        scan = run_workflow_scan(workflow, session.agent.config.timeout_seconds)
        memory = remember_scan(scan["summary"])
        append_audit({"kind": "workflow", "action": "run", "name": workflow})
        events = [{"type": "workflow_summary", "workflow": workflow, "summary": scan["summary"], "results": scan["results"]}]
        session.agent.add_user_message(_workflow_analysis_prompt(workflow, scan["summary"]))
        try:
            events.extend(_continue_session(session))
        except LlamaCppError as exc:
            events.append({"type": "notice", "content": f"Workflow completed. Model summary skipped: {exc}"})
        return {
            "ok": True,
            "session_id": session_id,
            "events": events,
            "memory": memory,
        }

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
        if settings.require_confirmation_for_modifying and payload.get("confirmed") is not True:
            if payload.get("confirmed") is False:
                append_audit({"kind": "action", "action": "declined", "name": "organize_apply"})
                return _declined_action_response(session_id, "Folder organization skipped.")
            reason = f"This will move {plan.get('move_count', 0)} files into ~/Organized by type."
            return {
                "ok": True,
                "session_id": session_id,
                "events": [
                    {
                        "type": "action_confirmation",
                        "action": "organize_apply",
                        "reason": reason,
                        "command": "internal file organization action",
                        "plan": _action_plan("organize_apply", "internal file organization action", reason),
                    }
                ],
            }
        result = apply_home_organization(plan)
        append_audit({"kind": "action", "action": "applied", "name": "organize_apply", "moved": len(result.get("applied", [])), "skipped": len(result.get("skipped", []))})
        session.pending_organize_plan = None
        return {"ok": True, "session_id": session_id, "events": [{"type": "organize_result", "result": result}]}

    return {"ok": False, "session_id": session_id, "error": f"Unknown action: {action}"}


def handle_export(payload: dict[str, Any]) -> dict[str, Any]:
    export_type = str(payload.get("type") or "memory").strip()
    memory = load_memory()
    if export_type == "audit":
        content = {"audit": memory.get("audit", [])}
    elif export_type == "profile":
        content = {
            "facts": memory.get("facts", {}),
            "profile": memory.get("profile", {}),
            "scan_history": memory.get("scan_history", []),
        }
    else:
        export_type = "memory"
        content = memory
    append_audit({"kind": "export", "action": "downloaded", "type": export_type})
    return {"ok": True, "type": export_type, "content": content}


def _declined_action_response(session_id: str, content: str) -> dict[str, Any]:
    return {
        "ok": True,
        "session_id": session_id,
        "events": [{"type": "notice", "content": content}],
    }


def _workflow_analysis_prompt(workflow: str, summary: dict[str, Any]) -> str:
    focus = {
        "display": "GPU, DRM, Wayland, X11, monitor detection, and compositor evidence",
        "audio": "PipeWire, WirePlumber, PulseAudio compatibility, ALSA devices, and default sinks",
        "network": "interfaces, routes, NetworkManager state, DNS symptoms, and link state",
        "services": "failed units, boot journal errors, timers, and whether a unit is harmless or important",
        "packages": "package updates, integrity warnings, locks, repository trust, and package-manager-specific next steps",
        "boot": "kernel, boot warnings, systemd timing, and repeated boot blockers",
        "storage": "filesystem usage, block devices, mounts, and safe cleanup order",
        "bluetooth": "Bluetooth service state, controller visibility, USB devices, and audio profile hints",
    }.get(workflow, "the selected subsystem")
    return (
        f"Analyze this {workflow} workflow scan. Focus on {focus}. "
        "Keep the answer concise, rank likely causes, and use the repair_plans as guidance. "
        "Do not suggest modifying commands unless permissions are enabled.\n\n"
        + json.dumps(summary, indent=2)
    )


def _ui_password() -> str:
    return str(os.environ.get("LTA_UI_PASSWORD") or "")


def _password_required() -> bool:
    return bool(_ui_password())


def _get_or_create_session(payload: dict[str, Any]) -> tuple[str, WebSession]:
    session_id = str(payload.get("session_id") or "")
    if session_id and session_id in SESSIONS:
        session = SESSIONS[session_id]
        _update_session_config(session, payload)
        return session_id, session

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
        max_tokens=_optional_int_payload(payload, "max_tokens", env_config.max_tokens),
        temperature=_optional_float_payload(payload, "temperature", env_config.temperature),
        top_p=_optional_float_payload(payload, "top_p", env_config.top_p),
        top_k=_optional_int_payload(payload, "top_k", env_config.top_k),
        repeat_penalty=_optional_float_payload(payload, "repeat_penalty", env_config.repeat_penalty),
    )
    session_id = secrets.token_urlsafe(16)
    SESSIONS[session_id] = WebSession(agent=Agent.create(config))
    return session_id, SESSIONS[session_id]


def _update_session_config(session: WebSession, payload: dict[str, Any]) -> None:
    old = session.agent.config
    base_url = str(payload.get("base_url") or old.base_url).strip()
    model = str(payload.get("model") or old.model).strip()
    api_key = str(payload.get("api_key") or "").strip() or old.api_key
    new_config = replace(
        old,
        base_url=base_url,
        model=model,
        api_key=api_key,
        max_tokens=_optional_int_payload(payload, "max_tokens", old.max_tokens),
        temperature=_optional_float_payload(payload, "temperature", old.temperature),
        top_p=_optional_float_payload(payload, "top_p", old.top_p),
        top_k=_optional_int_payload(payload, "top_k", old.top_k),
        repeat_penalty=_optional_float_payload(payload, "repeat_penalty", old.repeat_penalty),
    )
    if new_config != old:
        session.agent.config = new_config
        session.agent.client = LlamaCppClient(
            base_url=new_config.base_url,
            model=new_config.model,
            api_key=new_config.api_key,
        )


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
                result = _execute_command(session, command, session.agent.config.timeout_seconds, "auto_permitted", _fix_plan(command, reason))
                session.agent.record_command_result(result)
                events.append(_command_event(result))
                continue
            session.pending_command = command
            session.pending_reason = reason
            session.pending_plan = _fix_plan(command, reason)
            events.append({"type": "approval_required", "reason": reason, "command": command, "plan": session.pending_plan})
            return events

        safety = classify_command(command)
        if safety.decision == SafetyDecision.FORBIDDEN:
            note = f"Blocked forbidden command `{command}`: {safety.reason}"
            session.agent.record_controller_note(note)
            events.append({"type": "blocked", "content": note})
            continue

        if safety.decision == SafetyDecision.NEEDS_APPROVAL:
            if _permission_allows_command(command, settings) and not settings.require_confirmation_for_modifying:
                result = _execute_command(session, command, session.agent.config.timeout_seconds, "auto_permitted", _fix_plan(command, safety.reason))
                session.agent.record_command_result(result)
                events.append(_command_event(result))
                continue
            session.pending_command = command
            session.pending_reason = safety.reason
            session.pending_plan = _fix_plan(command, reason, safety.reason)
            events.append({"type": "approval_required", "reason": safety.reason, "command": command, "plan": session.pending_plan})
            return events

        result = _execute_command(session, command, session.agent.config.timeout_seconds, "safe_diagnostic")
        session.agent.record_command_result(result)
        events.append(_command_event(result))

    events.append({"type": "notice", "content": "Stopped after reaching the per-turn step limit."})
    return events


def _continue_session_stream(session: WebSession, emit) -> None:
    settings = load_settings()
    for _ in range(session.agent.config.max_steps):
        emit({"type": "status", "content": "LLM is thinking"})

        def on_delta(delta: str) -> None:
            emit({"type": "token", "content": delta})

        action = session.agent.next_action_stream(on_delta)
        action_type = action.get("type")

        if action_type == "message":
            emit({"type": "message", "content": str(action.get("content", "")).strip()})
            emit({"type": "done"})
            return

        if action_type not in {"command", "approval"}:
            emit({"type": "message", "content": str(action)})
            emit({"type": "done"})
            return

        reason = str(action.get("reason", "")).strip()
        command = str(action.get("command", "")).strip()
        if not command:
            emit({"type": "notice", "content": "The model requested an empty command."})
            emit({"type": "done"})
            return

        emit({"type": "proposed_command", "reason": reason, "command": command})

        if action_type == "approval":
            safety = classify_command(command)
            if safety.decision == SafetyDecision.FORBIDDEN:
                note = f"Blocked forbidden command `{command}`: {safety.reason}"
                session.agent.record_controller_note(note)
                emit({"type": "blocked", "content": note})
                continue
            if _permission_allows_command(command, settings) and not settings.require_confirmation_for_modifying:
                emit({"type": "status", "content": "Running approved command"})
                result = _execute_command(session, command, session.agent.config.timeout_seconds, "auto_permitted", _fix_plan(command, reason))
                session.agent.record_command_result(result)
                emit(_command_event(result))
                continue
            session.pending_command = command
            session.pending_reason = reason
            session.pending_plan = _fix_plan(command, reason)
            emit({"type": "approval_required", "reason": reason, "command": command, "plan": session.pending_plan})
            emit({"type": "done"})
            return

        safety = classify_command(command)
        if safety.decision == SafetyDecision.FORBIDDEN:
            note = f"Blocked forbidden command `{command}`: {safety.reason}"
            session.agent.record_controller_note(note)
            emit({"type": "blocked", "content": note})
            continue

        if safety.decision == SafetyDecision.NEEDS_APPROVAL:
            if _permission_allows_command(command, settings) and not settings.require_confirmation_for_modifying:
                emit({"type": "status", "content": "Running permitted command"})
                result = _execute_command(session, command, session.agent.config.timeout_seconds, "auto_permitted", _fix_plan(command, safety.reason))
                session.agent.record_command_result(result)
                emit(_command_event(result))
                continue
            session.pending_command = command
            session.pending_reason = safety.reason
            session.pending_plan = _fix_plan(command, reason, safety.reason)
            emit({"type": "approval_required", "reason": safety.reason, "command": command, "plan": session.pending_plan})
            emit({"type": "done"})
            return

        emit({"type": "status", "content": f"Running diagnostic: {command}"})
        result = _execute_command(session, command, session.agent.config.timeout_seconds, "safe_diagnostic")
        session.agent.record_command_result(result)
        emit(_command_event(result))

    emit({"type": "notice", "content": "Stopped after reaching the per-turn step limit."})
    emit({"type": "done"})


def _command_event(result: CommandResult) -> dict[str, Any]:
    return {
        "type": "command_result",
        "command": result.command,
        "exit_code": result.exit_code,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-4000:],
        "timed_out": result.timed_out,
    }


def _execute_command(
    session: WebSession,
    command: str,
    timeout_seconds: int,
    approval: str,
    plan: dict[str, Any] | None = None,
) -> CommandResult:
    result = run_command(command, timeout_seconds)
    append_audit(
        {
            "kind": "command",
            "action": approval,
            "command": command,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "plan": plan,
        }
    )
    return result


def _fix_plan(command: str, reason: str, safety_reason: str | None = None) -> dict[str, Any]:
    command_lower = command.lower()
    risk = "medium"
    rollback = "No automatic rollback is known. Review command output before continuing."
    verify = "Re-run the diagnostic command or scan after this action."
    backup = "Not required unless a config file is edited."
    if any(token in command_lower for token in ("apt ", "pacman ", "dnf ", "zypper ", "apk ")):
        risk = "high"
        rollback = "Package updates are not fully reversible. Use package manager history/cache if rollback is needed."
        verify = "Check package manager output and run the update check again."
    elif "systemctl" in command_lower or "service " in command_lower:
        risk = "medium"
        rollback = "Use the inverse systemctl action if the service change causes problems."
        verify = "Run systemctl status for the affected service."
    elif command_lower.startswith(("mv ", "cp ", "mkdir ", "touch ")):
        risk = "medium"
        rollback = "Move files back from the shown destination or remove only files created by this action."
        verify = "List the affected paths and confirm ownership and contents."
    return {
        "risk": risk,
        "reason": reason or safety_reason or "Approval required before modifying the system.",
        "backup": backup,
        "rollback": rollback,
        "verify": verify,
    }


def _action_plan(action: str, command: str, reason: str) -> dict[str, Any]:
    plan = _fix_plan(command, reason)
    if action == "organize_apply":
        plan.update(
            {
                "risk": "medium",
                "backup": "No backup is created; files are moved only if the destination does not exist.",
                "rollback": "Move files back from ~/Organized to their original paths shown in the plan.",
                "verify": "Review the Organization Result list after the action.",
            }
        )
    return plan


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
    if settings.allow_service_changes and _service_change_allowed(normalized):
        return True
    return False


def _service_change_allowed(command: str) -> bool:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens or any(token in {"|", "&&", "||", ";", "&"} for token in tokens):
        return False
    if tokens[0] == "sudo":
        tokens = tokens[1:]
    if not tokens:
        return False
    systemctl_ops = {
        "start",
        "stop",
        "restart",
        "reload",
        "try-restart",
        "reload-or-restart",
        "enable",
        "disable",
        "reenable",
        "mask",
        "unmask",
        "reset-failed",
    }
    service_ops = {"start", "stop", "restart", "reload"}
    if tokens[0] == "systemctl":
        if len(tokens) < 2 or tokens[1] not in systemctl_ops:
            return False
        if tokens[1] == "reset-failed":
            return True
        return len(tokens) >= 3 and _looks_like_unit(tokens[2])
    if tokens[0] == "service":
        return len(tokens) >= 3 and tokens[2] in service_ops
    return False


def _looks_like_unit(value: str) -> bool:
    if value.startswith("-") or "/" in value or value.endswith(".target"):
        return False
    return value.endswith((".service", ".socket", ".timer", ".path")) or "." not in value or "@" in value


def _int_payload(payload: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(payload.get(key, default))
    except (TypeError, ValueError):
        return default


def _float_payload(payload: dict[str, Any], key: str, default: float) -> float:
    try:
        return float(payload.get(key, default))
    except (TypeError, ValueError):
        return default


def _optional_int_payload(payload: dict[str, Any], key: str, default: int | None) -> int | None:
    if key in payload and payload.get(key) in (None, ""):
        return None
    try:
        return int(payload.get(key, default))
    except (TypeError, ValueError):
        return default


def _optional_float_payload(payload: dict[str, Any], key: str, default: float | None) -> float | None:
    if key in payload and payload.get(key) in (None, ""):
        return None
    try:
        return float(payload.get(key, default))
    except (TypeError, ValueError):
        return default


def _asset(name: str) -> bytes:
    return files("linux_troubleshoot_agent").joinpath("web_assets", name).read_bytes()


def _index_asset() -> bytes:
    html = _asset("index.html").decode("utf-8")
    html = html.replace("__LTA_AUTH_TOKEN__", auth_token())
    return html.encode("utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
