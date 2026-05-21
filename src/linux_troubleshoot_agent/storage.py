from __future__ import annotations

import copy
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from typing import Iterator


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
    "profile": {},
    "scan_history": [],
    "notes": [],
    "audit": [],
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


def auth_token() -> str:
    configured = os.environ.get("LTA_AUTH_TOKEN")
    if configured:
        return configured
    path = data_dir() / "auth.json"
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            token = str(payload.get("token") or "")
            if token:
                return token
        except json.JSONDecodeError:
            pass
    token = secrets.token_urlsafe(32)
    _write_json(path, {"token": token, "created_at": _now()})
    return token


def load_memory() -> dict[str, Any]:
    path = data_dir() / "memory.json"
    if not path.exists():
        memory = copy.deepcopy(DEFAULT_MEMORY)
        now = _now()
        memory["created_at"] = now
        memory["updated_at"] = now
        save_memory(memory)
        return memory
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        payload = copy.deepcopy(DEFAULT_MEMORY)
    for key, value in DEFAULT_MEMORY.items():
        payload.setdefault(key, copy.deepcopy(value))
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
    profile = memory.setdefault("profile", {})
    for key in (
        "session_type",
        "desktop",
        "gpu",
        "audio_server",
        "network_manager",
        "failed_services",
        "update_count",
    ):
        if summary.get(key) is not None:
            profile[key] = summary[key]
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


def append_audit(event: dict[str, Any]) -> dict[str, Any]:
    memory = load_memory()
    audit = memory.setdefault("audit", [])
    record = {"timestamp": _now(), **event}
    audit.append(record)
    del audit[:-100]
    save_memory(memory)
    return record


def list_chats(limit: int = 50) -> list[dict[str, Any]]:
    with _chat_connection() as conn:
        rows = conn.execute(
            """
            SELECT chats.id, chats.title, chats.session_id, chats.created_at, chats.updated_at,
                   COUNT(chat_items.id) AS item_count
            FROM chats
            LEFT JOIN chat_items ON chat_items.chat_id = chats.id
            GROUP BY chats.id
            ORDER BY chats.updated_at DESC
            LIMIT ?
            """,
            (max(1, min(limit, 200)),),
        ).fetchall()
    return [_chat_summary_from_row(row) for row in rows]


def create_chat(title: str = "New Chat") -> dict[str, Any]:
    now = _now()
    chat = {
        "id": f"chat-{secrets.token_urlsafe(12)}",
        "title": _clean_chat_title(title),
        "sessionId": None,
        "createdAt": now,
        "updatedAt": now,
        "items": [],
    }
    save_chat(chat)
    return chat


def load_chat(chat_id: str) -> dict[str, Any] | None:
    chat_id = str(chat_id or "").strip()
    if not chat_id:
        return None
    with _chat_connection() as conn:
        chat_row = conn.execute(
            "SELECT id, title, session_id, created_at, updated_at FROM chats WHERE id = ?",
            (chat_id,),
        ).fetchone()
        if chat_row is None:
            return None
        item_rows = conn.execute(
            """
            SELECT kind, title, body, pre, created_at
            FROM chat_items
            WHERE chat_id = ?
            ORDER BY position ASC, id ASC
            """,
            (chat_id,),
        ).fetchall()
    return _chat_from_rows(chat_row, item_rows)


def save_chat(chat: dict[str, Any]) -> dict[str, Any]:
    now = _now()
    chat_id = str(chat.get("id") or f"chat-{secrets.token_urlsafe(12)}").strip()
    title = _clean_chat_title(str(chat.get("title") or "New Chat"))
    created_at = str(chat.get("createdAt") or chat.get("created_at") or now)
    updated_at = str(chat.get("updatedAt") or chat.get("updated_at") or now)
    session_id = chat.get("sessionId", chat.get("session_id"))
    if session_id is not None:
        session_id = str(session_id)
    items = _clean_chat_items(chat.get("items", []))

    with _chat_connection() as conn:
        conn.execute(
            """
            INSERT INTO chats (id, title, session_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                session_id = excluded.session_id,
                updated_at = excluded.updated_at
            """,
            (chat_id, title, session_id, created_at, updated_at),
        )
        conn.execute("DELETE FROM chat_items WHERE chat_id = ?", (chat_id,))
        conn.executemany(
            """
            INSERT INTO chat_items (chat_id, position, kind, title, body, pre, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    chat_id,
                    index,
                    item["kind"],
                    item["title"],
                    item["body"],
                    item["pre"],
                    item["createdAt"],
                )
                for index, item in enumerate(items)
            ],
        )
    saved = load_chat(chat_id)
    return saved if saved is not None else create_chat(title)


def rename_chat(chat_id: str, title: str) -> dict[str, Any] | None:
    chat_id = str(chat_id or "").strip()
    title = _clean_chat_title(title)
    if not chat_id:
        return None
    with _chat_connection() as conn:
        result = conn.execute(
            "UPDATE chats SET title = ?, updated_at = ? WHERE id = ?",
            (title, _now(), chat_id),
        )
        if result.rowcount == 0:
            return None
    return load_chat(chat_id)


def delete_chat(chat_id: str) -> bool:
    chat_id = str(chat_id or "").strip()
    if not chat_id:
        return False
    with _chat_connection() as conn:
        result = conn.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
    return result.rowcount > 0


def _write_json(path: Path, payload: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def _chat_connection() -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(data_dir() / "chats.sqlite3")
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chats (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                session_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chat_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
                position INTEGER NOT NULL,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                pre TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_chat_items_chat_position ON chat_items(chat_id, position)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chats_updated ON chats(updated_at DESC)")
        yield conn
        conn.commit()
    finally:
        conn.close()


def _chat_summary_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "sessionId": row["session_id"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
        "itemCount": int(row["item_count"] or 0),
    }


def _chat_from_rows(chat_row: sqlite3.Row, item_rows: list[sqlite3.Row]) -> dict[str, Any]:
    return {
        "id": chat_row["id"],
        "title": chat_row["title"],
        "sessionId": chat_row["session_id"],
        "createdAt": chat_row["created_at"],
        "updatedAt": chat_row["updated_at"],
        "items": [
            {
                "kind": row["kind"],
                "title": row["title"],
                "body": row["body"],
                "pre": row["pre"],
                "createdAt": row["created_at"],
            }
            for row in item_rows
        ],
    }


def _clean_chat_title(title: str) -> str:
    cleaned = " ".join(str(title or "").replace("\n", " ").split()).strip()
    return (cleaned or "New Chat")[:80]


def _clean_chat_items(items: Any) -> list[dict[str, str]]:
    if not isinstance(items, list):
        return []
    cleaned: list[dict[str, str]] = []
    for item in items[-500:]:
        if not isinstance(item, dict):
            continue
        cleaned.append(
            {
                "kind": str(item.get("kind") or "agent")[:32],
                "title": str(item.get("title") or "")[:120],
                "body": str(item.get("body") or ""),
                "pre": str(item.get("pre") or ""),
                "createdAt": str(item.get("createdAt") or item.get("created_at") or _now()),
            }
        )
    return cleaned
