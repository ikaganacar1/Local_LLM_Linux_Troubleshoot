from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from enum import Enum


class SafetyDecision(str, Enum):
    SAFE = "safe"
    NEEDS_APPROVAL = "needs_approval"
    FORBIDDEN = "forbidden"


@dataclass(frozen=True)
class SafetyResult:
    decision: SafetyDecision
    reason: str


FORBIDDEN_PATTERNS = [
    r"\brm\s+-[^;&|]*r[^;&|]*f\s+/(?:\s|$)",
    r"\bmkfs(?:\.[a-z0-9]+)?\b",
    r"\bdd\s+.*\bof=/dev/",
    r"\bwipefs\b",
    r"\bshred\b",
    r"\bparted\b",
    r"\bfdisk\b",
    r"\bsgdisk\b",
    r"\bchmod\s+-R\s+\S*\s+/(?:\s|$)",
    r"\bchown\s+-R\s+\S*\s+/(?:\s|$)",
    r":\s*\(\s*\)\s*\{",
]

UNSAFE_TOKENS = {
    "sudo",
    "su",
    "doas",
    "rm",
    "mv",
    "cp",
    "install",
    "mkdir",
    "touch",
    "chmod",
    "chown",
    "chgrp",
    "tee",
    "nano",
    "vim",
    "nvim",
    "micro",
    "systemctl",
    "service",
    "kill",
    "pkill",
    "killall",
    "reboot",
    "shutdown",
    "poweroff",
    "mount",
    "umount",
    "modprobe",
    "rmmod",
    "ip",
    "nmcli",
    "pacman",
    "apt",
    "apt-get",
    "dnf",
    "zypper",
    "apk",
}

SAFE_FIRST_COMMANDS = {
    "uname",
    "cat",
    "journalctl",
    "dmesg",
    "lspci",
    "lsusb",
    "inxi",
    "xrandr",
    "kscreen-doctor",
    "hyprctl",
    "nvidia-smi",
    "lsmod",
    "pactl",
    "wpctl",
    "ls",
    "stat",
    "df",
    "free",
    "lsblk",
    "findmnt",
    "hostnamectl",
    "loginctl",
    "glxinfo",
    "vulkaninfo",
    "grep",
    "rg",
    "awk",
    "sed",
    "head",
    "tail",
}

SAFE_SYSTEMCTL_SUBCOMMANDS = {
    "status",
    "show",
    "list-units",
    "list-unit-files",
    "list-timers",
    "--failed",
    "is-active",
    "is-enabled",
}

SAFE_PACMAN_FLAGS = ("-Q", "-Qs", "-Qk", "-Qi", "-Ql")
SAFE_APT_PREFIXES = (("list", "--upgradable"), ("show",), ("policy",), ("search",))
SAFE_APT_GET_PREFIXES = (("--just-print",), ("--simulate",), ("-s",))
SAFE_DNF_PREFIXES = (("check-update",), ("list", "updates"), ("info",), ("search",))
SAFE_ZYPPER_PREFIXES = (("list-updates",), ("search",), ("info",))
SAFE_APK_PREFIXES = (("version", "-l"), ("info",), ("search",))
SAFE_IP_SUBCOMMANDS = {"a", "addr", "address", "route", "link", "-brief"}
SAFE_NMCLI_PREFIXES = (("device", "status"), ("connection", "show"), ("general", "status"))
SHELL_EXPANSION_PATTERNS = [
    r"\$\(",
    r"`",
    r"\$\{",
    r"<\(",
    r">\(",
]


def classify_command(command: str) -> SafetyResult:
    normalized = command.strip()
    if not normalized:
        return SafetyResult(SafetyDecision.FORBIDDEN, "Empty commands are not runnable.")

    lowered = normalized.lower()
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, lowered):
            return SafetyResult(
                SafetyDecision.FORBIDDEN,
                "This command matches a destructive disk, filesystem, or permission pattern.",
            )

    for pattern in SHELL_EXPANSION_PATTERNS:
        if re.search(pattern, normalized):
            return SafetyResult(
                SafetyDecision.NEEDS_APPROVAL,
                "Shell expansion or substitution can run hidden commands.",
            )

    if re.search(r"(^|[^<])>{1,2}[^>]", normalized) or "<<" in normalized:
        return SafetyResult(
            SafetyDecision.NEEDS_APPROVAL,
            "Shell redirection can overwrite or create files.",
        )

    try:
        tokens = shlex.split(normalized)
    except ValueError as exc:
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, f"Could not parse command: {exc}")

    if not tokens:
        return SafetyResult(SafetyDecision.FORBIDDEN, "Empty commands are not runnable.")

    command_segments = _split_pipeline_tokens(tokens)
    for segment in command_segments:
        if not segment:
            continue
        result = _classify_segment(segment)
        if result.decision != SafetyDecision.SAFE:
            return result

    return SafetyResult(SafetyDecision.SAFE, "Command appears to be read-only diagnostics.")


def _split_pipeline_tokens(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = [[]]
    for token in tokens:
        if token in {"|", "&&", "||", ";"}:
            segments.append([])
            continue
        segments[-1].append(token)
    return segments


def _classify_segment(tokens: list[str]) -> SafetyResult:
    first = tokens[0]
    if first == "systemctl":
        if len(tokens) > 1 and tokens[1] in SAFE_SYSTEMCTL_SUBCOMMANDS:
            return SafetyResult(SafetyDecision.SAFE, "Read-only systemctl query.")
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "systemctl can modify services.")

    if first == "pacman":
        if len(tokens) > 1 and any(tokens[1].startswith(flag) for flag in SAFE_PACMAN_FLAGS):
            return SafetyResult(SafetyDecision.SAFE, "Read-only pacman query.")
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "pacman can install, remove, or upgrade packages.")

    if first in {"apt", "apt-get"}:
        if _starts_with_any(tokens[1:], SAFE_APT_PREFIXES + SAFE_APT_GET_PREFIXES):
            return SafetyResult(SafetyDecision.SAFE, "Read-only apt query.")
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "apt can install, remove, upgrade, or change package metadata.")

    if first == "dnf":
        if _starts_with_any(tokens[1:], SAFE_DNF_PREFIXES):
            return SafetyResult(SafetyDecision.SAFE, "Read-only dnf query.")
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "dnf can install, remove, or upgrade packages.")

    if first == "zypper":
        if _starts_with_any(tokens[1:], SAFE_ZYPPER_PREFIXES):
            return SafetyResult(SafetyDecision.SAFE, "Read-only zypper query.")
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "zypper can install, remove, or upgrade packages.")

    if first == "apk":
        if _starts_with_any(tokens[1:], SAFE_APK_PREFIXES):
            return SafetyResult(SafetyDecision.SAFE, "Read-only apk query.")
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "apk can install, remove, or upgrade packages.")

    if first == "ip":
        if len(tokens) > 1 and tokens[1] in SAFE_IP_SUBCOMMANDS and "set" not in tokens:
            return SafetyResult(SafetyDecision.SAFE, "Read-only ip query.")
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "ip can change network state.")

    if first == "nmcli":
        if len(tokens) >= 3 and tuple(tokens[1:3]) in SAFE_NMCLI_PREFIXES:
            return SafetyResult(SafetyDecision.SAFE, "Read-only nmcli query.")
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "nmcli can change network configuration.")

    if first == "sed" and "-i" in tokens:
        return SafetyResult(SafetyDecision.NEEDS_APPROVAL, "sed -i edits files.")

    if first in UNSAFE_TOKENS:
        return SafetyResult(
            SafetyDecision.NEEDS_APPROVAL,
            f"`{first}` can modify the system or user files.",
        )

    if first in SAFE_FIRST_COMMANDS:
        return SafetyResult(SafetyDecision.SAFE, "Known read-only diagnostic command.")

    return SafetyResult(
        SafetyDecision.NEEDS_APPROVAL,
        f"`{first}` is not in the read-only allowlist.",
    )


def _starts_with_any(tokens: list[str], prefixes: tuple[tuple[str, ...], ...]) -> bool:
    return any(tuple(tokens[: len(prefix)]) == prefix for prefix in prefixes)
