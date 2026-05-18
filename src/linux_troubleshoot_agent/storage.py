from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class PermissionSettings:
    auto_run_readonly_scan: bool = True
    allow_package_updates: bool = False
    allow_service_changes: bool = False
    allow_personal_folder_organize: bool = False
    require_confirmation_for_modifying: bool = True


DEFAULT_MEMORY: dict[str, Any] = {
    "created_at": None,
    "updated_at": None,
    "facts": {},
    "scan_history": [],
    "notes": [],
}


def data_dir() -> Path:
    configured = os.environ.get("LTA_DATA_DIR")
    if configured:
        root = Path(configured).expanduser()
    else:
        root = Path.cwd() / ".lta_data"
    root.mkdir(parents=True, exist_ok=True)
    return root


def load_settings() -> PermissionSettings:
    path = data_dir() / "settings.json"
    if not path.exists():
        return PermissionSettings()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return PermissionSettings()
    return PermissionSettings(
        auto_run_readonly_scan=bool(payload.get("auto_run_readonly_scan", True)),
        allow_package_updates=bool(payload.get("allow_package_updates", False)),
        allow_service_changes=bool(payload.get("allow_service_changes", False)),
        allow_personal_folder_organize=bool(payload.get("allow_personal_folder_organize", False)),
        require_confirmation_for_modifying=bool(payload.get("require_confirmation_for_modifying", True)),
    )


def save_settings(settings: PermissionSettings) -> None:
    _write_json(data_dir() / "settings.json", asdict(settings))


def load_memory() -> dict[str, Any]:
    path = data_dir() / "memory.json"
    if not path.exists():
        memory = dict(DEFAULT_MEMORY)
        now = _now()
        memory["created_at"] = now
        memory["updated_at"] = now
        save_memory(memory)
        return memory
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        payload = dict(DEFAULT_MEMORY)
    for key, value in DEFAULT_MEMORY.items():
        payload.setdefault(key, value)
    return payload


def save_memory(memory: dict[str, Any]) -> None:
    memory["updated_at"] = _now()
    if memory.get("created_at") is None:
        memory["created_at"] = memory["updated_at"]
    _write_json(data_dir() / "memory.json", memory)


def remember_scan(summary: dict[str, Any]) -> dict[str, Any]:
    memory = load_memory()
    facts = memory.setdefault("facts", {})
    for key in ("os_id", "os_name", "os_version", "kernel", "package_manager"):
        if summary.get(key):
            facts[key] = summary[key]
    history = memory.setdefault("scan_history", [])
    history.append(
        {
            "timestamp": _now(),
            "os_name": summary.get("os_name"),
            "kernel": summary.get("kernel"),
            "package_manager": summary.get("package_manager"),
            "issue_count": len(summary.get("issues", [])),
        }
    )
    del history[:-20]
    save_memory(memory)
    return memory


def _write_json(path: Path, payload: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
