from __future__ import annotations

import argparse
import sys

from .agent import Agent
from .config import Config
from .llama_cpp_client import LlamaCppError
from .safety import SafetyDecision, classify_command
from .shell import run_command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="linux-troubleshoot-agent",
        description="Safe local Linux troubleshooting agent backed by llama.cpp.",
    )
    parser.add_argument("problem", nargs="*", help="Optional initial problem statement.")
    parser.add_argument("--check-command", help="Classify a command without running it.")
    args = parser.parse_args(argv)

    if args.check_command:
        result = classify_command(args.check_command)
        print(f"{result.decision.value}: {result.reason}")
        return 0 if result.decision != SafetyDecision.FORBIDDEN else 2

    config = Config.from_env()
    agent = Agent.create(config)

    print("Local Linux Troubleshooting Agent")
    print(f"llama.cpp endpoint: {config.base_url}")
    print("Type a problem, or `exit` to quit.")
    print()

    initial = " ".join(args.problem).strip()
    if initial:
        _run_turn(agent, initial)

    while True:
        try:
            user_input = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not user_input:
            continue
        if user_input.lower() in {"exit", "quit"}:
            return 0

        _run_turn(agent, user_input)


def _run_turn(agent: Agent, user_input: str) -> None:
    agent.add_user_message(user_input)

    for _ in range(agent.config.max_steps):
        try:
            action = agent.next_action()
        except LlamaCppError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return

        action_type = action.get("type")
        if action_type == "message":
            print(action.get("content", "").strip())
            return

        if action_type in {"command", "approval"}:
            reason = str(action.get("reason", "")).strip()
            command = str(action.get("command", "")).strip()
            if not command:
                print("The model requested an empty command; stopping this turn.")
                return

            print(f"Reason: {reason}")
            print(f"Command: {command}")

            if action_type == "approval":
                safety = classify_command(command)
                if safety.decision == SafetyDecision.FORBIDDEN:
                    note = f"Blocked forbidden command `{command}`: {safety.reason}"
                    agent.record_controller_note(note)
                    print(note)
                    return
                if not _confirm("This command may modify the system. Run it?"):
                    agent.record_controller_note(f"User declined command `{command}`.")
                    print("Skipped.")
                    return
                result = run_command(command, agent.config.timeout_seconds)
                agent.record_command_result(result)
                _print_command_summary(result.exit_code)
                continue

            status, result = agent.handle_command(command)
            if status.startswith("approval_required"):
                print(status.removeprefix("approval_required: ").strip())
                safety = classify_command(command)
                if safety.decision == SafetyDecision.FORBIDDEN:
                    note = f"Blocked forbidden command `{command}`: {safety.reason}"
                    agent.record_controller_note(note)
                    print(note)
                    return
                if not _confirm("This command is not automatically classified as read-only. Run it?"):
                    agent.record_controller_note(f"User declined command `{command}`.")
                    print("Skipped.")
                    return
                result = run_command(command, agent.config.timeout_seconds)
                agent.record_command_result(result)
                _print_command_summary(result.exit_code)
                continue

            if result is None:
                print(status)
                continue

            _print_command_summary(result.exit_code)
            continue

    print("Stopped after reaching the per-turn step limit.")


def _confirm(prompt: str) -> bool:
    answer = input(f"{prompt} [y/N] ").strip().lower()
    return answer in {"y", "yes"}


def _print_command_summary(exit_code: int) -> None:
    print(f"Command finished with exit code {exit_code}.")


if __name__ == "__main__":
    raise SystemExit(main())
