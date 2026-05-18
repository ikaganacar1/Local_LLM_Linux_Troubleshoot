from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .shell import CommandResult, run_command


@dataclass(frozen=True)
class ScanCommand:
    name: str
    command: str
    timeout: int = 20


BASE_SCAN_COMMANDS = [
    ScanCommand("kernel", "uname -a"),
    ScanCommand("os_release", "cat /etc/os-release"),
    ScanCommand("failed_services", "systemctl --failed --no-pager"),
    ScanCommand("journal_errors", "journalctl -p 3 -xb --no-pager -n 80"),
    ScanCommand("disk_space", "df -hT"),
    ScanCommand("block_devices", "lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINTS"),
    ScanCommand("memory", "free -h"),
    ScanCommand("network", "ip -brief addr"),
    ScanCommand("routes", "ip route"),
    ScanCommand("gpu", "lspci -k"),
    ScanCommand("audio", "pactl info"),
    ScanCommand("hostname", "hostnamectl"),
    ScanCommand("network_manager", "systemctl is-active NetworkManager"),
]

WORKFLOWS: dict[str, list[ScanCommand]] = {
    "display": [
        ScanCommand("gpu", "lspci -k"),
        ScanCommand("drm_journal", "journalctl -b --no-pager -n 120"),
        ScanCommand("monitors_x11", "xrandr"),
        ScanCommand("monitors_kde", "kscreen-doctor -o"),
        ScanCommand("monitors_hyprland", "hyprctl monitors"),
    ],
    "audio": [
        ScanCommand("pipewire", "systemctl --user status pipewire --no-pager"),
        ScanCommand("wireplumber", "systemctl --user status wireplumber --no-pager"),
        ScanCommand("pactl", "pactl info"),
        ScanCommand("sinks", "pactl list short sinks"),
        ScanCommand("wpctl", "wpctl status"),
    ],
    "network": [
        ScanCommand("addresses", "ip -brief addr"),
        ScanCommand("routes", "ip route"),
        ScanCommand("network_manager", "nmcli device status"),
        ScanCommand("network_journal", "journalctl -u NetworkManager -b --no-pager -n 120"),
    ],
    "services": [
        ScanCommand("failed_services", "systemctl --failed --no-pager"),
        ScanCommand("journal_errors", "journalctl -p 3 -xb --no-pager -n 120"),
        ScanCommand("timers", "systemctl list-timers --no-pager"),
    ],
    "packages": [
        ScanCommand("package_integrity_pacman", "pacman -Qk"),
        ScanCommand("updates_pacman", "pacman -Qu"),
        ScanCommand("updates_apt", "apt list --upgradable"),
    ],
    "boot": [
        ScanCommand("kernel", "uname -a"),
        ScanCommand("boot_errors", "journalctl -b -p warning --no-pager -n 160"),
        ScanCommand("boot_time", "systemd-analyze"),
    ],
    "storage": [
        ScanCommand("disk_space", "df -hT"),
        ScanCommand("block_devices", "lsblk -o NAME,SIZE,FSTYPE,TYPE,MOUNTPOINTS"),
        ScanCommand("mounts", "findmnt"),
    ],
    "bluetooth": [
        ScanCommand("bluetooth_service", "systemctl status bluetooth --no-pager"),
        ScanCommand("bluetooth_journal", "journalctl -u bluetooth -b --no-pager -n 120"),
        ScanCommand("usb", "lsusb"),
    ],
}


def run_system_scan(timeout_seconds: int = 30) -> dict[str, Any]:
    commands = list(BASE_SCAN_COMMANDS)
    package_manager = detect_package_manager()
    update_check = update_check_command(package_manager)
    if update_check:
        commands.append(ScanCommand("updates", update_check, timeout=45))

    results: dict[str, dict[str, Any]] = {}
    for item in commands:
        result = run_command(item.command, min(timeout_seconds, item.timeout))
        results[item.name] = _result_dict(result)

    summary = summarize_scan(results, package_manager)
    return {"summary": summary, "results": results}


def run_workflow_scan(workflow: str, timeout_seconds: int = 30) -> dict[str, Any]:
    commands = WORKFLOWS.get(workflow)
    if not commands:
        return {"summary": {"workflow": workflow, "issues": []}, "results": {}}

    results: dict[str, dict[str, Any]] = {}
    for item in commands:
        result = run_command(item.command, min(timeout_seconds, item.timeout))
        results[item.name] = _result_dict(result)

    package_manager = detect_package_manager()
    summary = summarize_scan(results, package_manager)
    summary["workflow"] = workflow
    return {"summary": summary, "results": results}


def summarize_scan(results: dict[str, dict[str, Any]], package_manager: str | None) -> dict[str, Any]:
    os_info = parse_os_release(results.get("os_release", {}).get("stdout", ""))
    kernel = first_line(results.get("kernel", {}).get("stdout", ""))
    issues = detect_issues(results, package_manager)
    profile = infer_profile(results, issues, package_manager)
    return {
        "os_id": os_info.get("ID"),
        "os_name": os_info.get("PRETTY_NAME") or os_info.get("NAME"),
        "os_version": os_info.get("VERSION_ID"),
        "kernel": kernel,
        "package_manager": package_manager,
        "issues": issues,
        **profile,
    }


def detect_package_manager() -> str | None:
    if shutil.which("pacman"):
        return "pacman"
    if shutil.which("apt"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("zypper"):
        return "zypper"
    if shutil.which("apk"):
        return "apk"
    return None


def update_check_command(package_manager: str | None) -> str | None:
    if package_manager == "pacman":
        return "pacman -Qu"
    if package_manager == "apt":
        return "apt list --upgradable"
    if package_manager == "dnf":
        return "dnf check-update"
    if package_manager == "zypper":
        return "zypper list-updates"
    if package_manager == "apk":
        return "apk version -l '<'"
    return None


def update_apply_command(package_manager: str | None) -> str | None:
    if package_manager == "pacman":
        return "sudo pacman -Syu --noconfirm"
    if package_manager == "apt":
        return "sudo apt update && sudo apt upgrade -y"
    if package_manager == "dnf":
        return "sudo dnf upgrade -y"
    if package_manager == "zypper":
        return "sudo zypper update -y"
    if package_manager == "apk":
        return "sudo apk update && sudo apk upgrade"
    return None


def detect_issues(results: dict[str, dict[str, Any]], package_manager: str | None) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    failed = results.get("failed_services", {})
    if failed.get("exit_code") == 0 and "0 loaded units listed" not in failed.get("stdout", ""):
        stdout = failed.get("stdout", "").strip()
        if stdout:
            issues.append(
                {
                    "severity": "high",
                    "title": "Failed systemd services",
                    "detail": trim(stdout, 900),
                    "next_step": "Open the failed service status and journal before restarting or disabling anything.",
                }
            )

    journal = results.get("journal_errors", {})
    if journal.get("exit_code") == 0 and journal.get("stdout", "").strip():
        issues.append(
            {
                "severity": "medium",
                "title": "Recent boot errors in journal",
                "detail": trim(journal.get("stdout", ""), 900),
                "next_step": "Inspect the repeated errors first; one root cause often creates several lines.",
            }
        )

    disk = results.get("disk_space", {}).get("stdout", "")
    full_lines = []
    for line in disk.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[5] != "/boot":
            use = parts[5].rstrip("%")
            if use.isdigit() and int(use) >= 90:
                full_lines.append(line)
    if full_lines:
        issues.append(
            {
                "severity": "high",
                "title": "Filesystem nearly full",
                "detail": "\n".join(full_lines),
                "next_step": "Review large files and caches before deleting anything.",
            }
        )

    updates = update_result_for(results, package_manager)
    update_count = count_updates(package_manager, updates.get("stdout", ""), updates.get("exit_code", 0))
    if update_count > 0:
        issues.append(
            {
                "severity": "medium",
                "title": "Package updates available",
                "detail": f"{update_count} update entries detected for {package_manager}.",
                "next_step": "Use the update action if package update permission is enabled.",
            }
        )

    for issue in package_issues(results, package_manager):
        issues.append(issue)

    if results.get("network", {}).get("exit_code") != 0:
        issues.append(
            {
                "severity": "medium",
                "title": "Network status command failed",
                "detail": trim(results.get("network", {}).get("stderr", ""), 500),
                "next_step": "Check whether iproute2 is installed and whether NetworkManager or systemd-networkd is active.",
            }
        )

    return issues


def infer_profile(
    results: dict[str, dict[str, Any]],
    issues: list[dict[str, str]],
    package_manager: str | None,
) -> dict[str, Any]:
    hostname = results.get("hostname", {}).get("stdout", "")
    gpu = first_matching_line(results.get("gpu", {}).get("stdout", ""), ("VGA", "3D", "Display"))
    audio = results.get("audio", {}).get("stdout", "")
    network_manager = results.get("network_manager", {}).get("stdout", "").strip()
    update_result = update_result_for(results, package_manager)
    return {
        "session_type": _extract_hostnamectl(hostname, "Operating System") or None,
        "desktop": os.environ.get("XDG_CURRENT_DESKTOP") or os.environ.get("DESKTOP_SESSION"),
        "gpu": gpu,
        "audio_server": first_line(audio),
        "network_manager": network_manager or None,
        "failed_services": _failed_service_names(results.get("failed_services", {}).get("stdout", "")),
        "update_count": count_updates(
            package_manager,
            update_result.get("stdout", ""),
            update_result.get("exit_code", 0),
        )
        if update_result
        else 0,
    }


def package_issues(results: dict[str, dict[str, Any]], package_manager: str | None) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    if package_manager == "pacman":
        integrity = results.get("package_integrity_pacman", {})
        stdout = integrity.get("stdout", "")
        broken = [line for line in stdout.splitlines() if "0 missing files" not in line and "backup file" not in line]
        if integrity.get("exit_code") not in (None, 0) or broken:
            issues.append(
                {
                    "severity": "medium",
                    "title": "Pacman package integrity warnings",
                    "detail": trim("\n".join(broken) or integrity.get("stderr", ""), 900),
                    "next_step": "Inspect affected packages with pacman -Qk before reinstalling anything.",
                }
            )
    if package_manager == "apt":
        updates = update_result_for(results, package_manager)
        stderr = updates.get("stderr", "")
        if "NO_PUBKEY" in stderr or "EXPKEYSIG" in stderr:
            issues.append(
                {
                    "severity": "high",
                    "title": "APT repository signature problem",
                    "detail": trim(stderr, 900),
                    "next_step": "Fix repository signing keys before applying updates.",
                }
            )
        if "Could not get lock" in stderr:
            issues.append(
                {
                    "severity": "medium",
                    "title": "APT lock is held",
                    "detail": trim(stderr, 700),
                    "next_step": "Wait for the active package process to finish before retrying.",
                }
            )
    return issues


def update_result_for(results: dict[str, dict[str, Any]], package_manager: str | None) -> dict[str, Any]:
    if results.get("updates"):
        return results["updates"]
    workflow_key = f"updates_{package_manager}" if package_manager else ""
    if workflow_key and results.get(workflow_key):
        return results[workflow_key]
    return {}


def count_updates(package_manager: str | None, stdout: str, exit_code: int) -> int:
    lines = [line for line in stdout.splitlines() if line.strip()]
    if package_manager == "apt":
        return max(0, len([line for line in lines if "/" in line and not line.startswith("Listing")]))
    if package_manager == "dnf":
        return max(0, len([line for line in lines if not line.startswith(("Last metadata", "Security:"))]))
    return len(lines)


def parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def first_line(text: str) -> str:
    return next((line.strip() for line in text.splitlines() if line.strip()), "")


def first_matching_line(text: str, needles: tuple[str, ...]) -> str:
    for line in text.splitlines():
        if any(needle in line for needle in needles):
            return line.strip()
    return ""


def _extract_hostnamectl(text: str, key: str) -> str:
    prefix = f"{key}:"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped.split(":", 1)[1].strip()
    return ""


def _failed_service_names(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(".service"):
            names.append(parts[0])
    return names[:20]


def trim(text: str, max_chars: int) -> str:
    text = text.strip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[truncated]"


def _result_dict(result: CommandResult) -> dict[str, Any]:
    return {
        "command": result.command,
        "exit_code": result.exit_code,
        "stdout": result.stdout[-12000:],
        "stderr": result.stderr[-4000:],
        "timed_out": result.timed_out,
    }


def plan_home_organization(home: Path | None = None) -> dict[str, Any]:
    root = home or _default_home_for_file_actions()
    sources = [root / "Downloads", root / "Desktop"]
    categories = {
        "Documents": {".pdf", ".doc", ".docx", ".odt", ".txt", ".md", ".rtf", ".xls", ".xlsx", ".ods", ".ppt", ".pptx"},
        "Images": {".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".heic", ".bmp"},
        "Videos": {".mp4", ".mkv", ".mov", ".webm", ".avi"},
        "Audio": {".mp3", ".flac", ".wav", ".ogg", ".m4a"},
        "Archives": {".zip", ".tar", ".gz", ".xz", ".7z", ".rar", ".bz2"},
        "Code": {".py", ".js", ".ts", ".sh", ".rs", ".go", ".c", ".cpp", ".h", ".java"},
    }
    moves: list[dict[str, str]] = []
    for source_dir in sources:
        if not source_dir.exists() or not source_dir.is_dir():
            continue
        for path in source_dir.iterdir():
            if not path.is_file() or path.name.startswith("."):
                continue
            category = "Other"
            suffix = path.suffix.lower()
            for name, suffixes in categories.items():
                if suffix in suffixes:
                    category = name
                    break
            destination = root / "Organized" / category / path.name
            moves.append({"source": str(path), "destination": str(destination), "category": category})
    return {"home": str(root), "move_count": len(moves), "moves": moves[:200]}


def apply_home_organization(plan: dict[str, Any]) -> dict[str, Any]:
    applied: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []
    for item in plan.get("moves", []):
        source = Path(str(item.get("source", ""))).expanduser()
        destination = Path(str(item.get("destination", ""))).expanduser()
        if not source.exists() or not source.is_file():
            skipped.append({"source": str(source), "reason": "source missing or not a file"})
            continue
        if destination.exists():
            skipped.append({"source": str(source), "reason": "destination exists"})
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        source.rename(destination)
        applied.append({"source": str(source), "destination": str(destination)})
    return {"applied": applied, "skipped": skipped}


def _default_home_for_file_actions() -> Path:
    configured = os.environ.get("LTA_HOST_HOME")
    if configured:
        return Path(configured).expanduser()
    return Path.home()
