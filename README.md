# Local LLM Linux Troubleshooter

![Local LLM Linux Troubleshooter banner](banner.png)

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![llama.cpp](https://img.shields.io/badge/llama.cpp-OpenAI%20compatible-222222)
![Docker](https://img.shields.io/badge/Docker-restart%20always-2496ED?logo=docker&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-Arch%20%7C%20Ubuntu%20%7C%20Alpine-FCC624?logo=linux&logoColor=111111)
![GUI](https://img.shields.io/badge/GUI-local%20web%20app-4B5563)

A local web app for diagnosing Linux problems with a llama.cpp model. It can scan the host, read logs, explain likely causes, propose repair steps, and ask before doing anything that changes the system.

The default llama.cpp endpoint is:

```text
http://127.0.0.1:11435/v1
```

## What It Does

- Runs read-only diagnostics for services, packages, boot, storage, network, display, audio, and Bluetooth.
- Streams model output in the chat, including collapsible reasoning when the model exposes thinking tokens.
- Keeps chat history in the browser and local scan memory in `.lta_data/`.
- Lets you configure model, context/token settings, permissions, and theme from the GUI.
- Supports package-manager-aware update checks for common Linux distros.
- Uses a safety controller before executing commands.

## Docker Setup

Start the app as a local restart-always service:

```bash
docker compose up -d --build
```

Open:

```text
http://127.0.0.1:28765/
```

The compose setup is intentionally local:

- GUI binds to `127.0.0.1:28765`.
- `network_mode: host` lets the container reach llama.cpp on `127.0.0.1:11435`.
- `pid: host`, `privileged: true`, and `LTA_COMMAND_TARGET=host` allow host diagnostics instead of container-only checks.
- `${HOME}` is mounted at `/host-home` for folder organization.
- `.lta_data/` stores local memory and audit data.

Set a local UI password if other people can access your browser session:

```bash
export LTA_UI_PASSWORD='choose-a-local-password'
docker compose up -d --build
```

## Run Without Docker

```bash
PYTHONPATH=src python3 -m linux_troubleshoot_agent.web
```

Useful defaults:

```bash
export LLAMA_CPP_BASE_URL=http://127.0.0.1:11435/v1
export LLAMA_CPP_MODEL=local-model
export LTA_MAX_TOKENS=4096
export LTA_TEMPERATURE=0.2
export LTA_TOP_P=0.95
export LTA_TOP_K=40
export LTA_REPEAT_PENALTY=1.1
```

## CLI

Ask a troubleshooting question:

```bash
PYTHONPATH=src python3 -m linux_troubleshoot_agent "HDMI monitor is not detected"
```

Check command safety classification:

```bash
PYTHONPATH=src python3 -m linux_troubleshoot_agent --check-command "journalctl -p 3 -xb"
```

## Tests

Offline regression tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Live tests, kept separate because they need Docker and llama.cpp running:

```bash
LTA_APP_URL=http://127.0.0.1:28765 \
LTA_LLAMA_BASE_URL=http://127.0.0.1:11435/v1 \
LTA_LIVE_MODEL=Qwen3-Coder-Next-UD-IQ3_XXS \
PYTHONPATH=src python3 -m unittest discover -s integration_tests -v
```

## Safety Notes

Read-only commands run first. Package installs/removals, service changes, config edits, folder moves, process kills, reboot/power actions, and other modifying commands require permission in the GUI.

The command runner avoids `shell=True`, rejects unsupported shell syntax, and blocks known destructive patterns. Approved actions are logged to the local audit trail.

For commands that need `sudo`, start the GUI from a terminal so password prompts are visible if your sudo session is not already active.

## Project Layout

```text
src/linux_troubleshoot_agent/   Python package, GUI server, safety checks, scanner
src/linux_troubleshoot_agent/web_assets/   Browser UI
tests/                          Offline regression tests
integration_tests/              Live app and llama.cpp tests
prompts/                        Agent prompt and short description
compose.yaml                    Local Docker service
```

This checkout uses a local git wrapper. If normal `git status` stops at `/mnt`, use:

```bash
scripts/git-local status
```
