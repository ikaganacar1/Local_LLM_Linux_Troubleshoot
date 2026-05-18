# Local Linux Troubleshooting Agent

A safe local Linux troubleshooting agent focused on Arch Linux and similar systems. It uses a ready llama.cpp OpenAI-compatible server for the model and runs local diagnostic commands through a safety controller.

## Files

- `prompts/system_prompt.txt`: Full system prompt for the agent runtime.
- `prompts/description.txt`: Short agent description for UI, metadata, or config summaries.
- `src/linux_troubleshoot_agent/`: Python agent, llama.cpp client, command safety checks, CLI, and browser GUI.

## GUI

Run the browser UI:

```bash
python -m linux_troubleshoot_agent.web
```

Then open:

```text
http://127.0.0.1:28765/
```

The llama.cpp base URL defaults to:

```text
http://127.0.0.1:11435/v1
```

You can also set defaults before launching:

```bash
export LLAMA_CPP_BASE_URL=http://127.0.0.1:11435/v1
export LLAMA_CPP_MODEL=local-model
export LTA_MAX_TOKENS=4096
export LTA_TEMPERATURE=0.2
export LTA_TOP_P=0.95
export LTA_TOP_K=40
export LTA_REPEAT_PENALTY=1.1
python -m linux_troubleshoot_agent.web
```

The GUI defaults to dark mode and streams LLM output into the chat as tokens arrive. Use `Settings` to configure:

- llama.cpp base URL and active model
- model list from the configured `/v1/models` endpoint
- max tokens, temperature, top-p, top-k, and repeat penalty; leave fields blank to use llama.cpp server defaults
- action permissions
- light/dark mode

Chats are kept in browser local storage, restored after page refresh, and listed in the right-side chat history. New chats are automatically named from the first message with a local LLM-generated title when available.

The GUI also includes a workflow rail and issue dashboard. Workflow buttons run focused read-only diagnostics for display, audio, network, services, packages, boot, storage, and Bluetooth.

## Docker

Run it as a restart-always local service:

```bash
docker compose up -d --build
```

Then open:

```text
http://127.0.0.1:28765/
```

The Docker service is configured with:

- `restart: always`
- unusual GUI port `28765`
- bound to `127.0.0.1` by default, so the privileged GUI is only reachable from this PC
- `network_mode: host`, so llama.cpp at `http://127.0.0.1:11435/v1` is reachable from the container
- `pid: host` and `privileged: true`, so diagnostics can access the PC rather than only the container
- `LTA_COMMAND_TARGET=host`, so command execution uses `nsenter` into the host namespaces
- `${HOME}:/host-home`, so folder organization works on your real home directory

Local memory is stored in `.lta_data/` and mounted into the container.

The served page receives a local API token and all POST APIs require that token. POST requests with an untrusted `Origin` or `Referer` are rejected.

## Automatic Maintenance

The GUI includes buttons for:

- `Scan System`: read-only scan for OS, kernel, failed services, journal errors, disk space, network, GPU/audio basics, and available updates.
- `Check Updates`: distro-aware read-only package update check.
- `Apply Updates`: runs the detected package manager update command when package update permission is enabled.
- `Plan Folders`: previews moves from `~/Downloads` and `~/Desktop` into `~/Organized` by file type.
- `Organize`: applies the folder plan when personal folder organization permission is enabled.

The agent stores local memory in `.lta_data/` by default. Set `LTA_DATA_DIR` to use a different location.

For commands that use `sudo`, launch the GUI from a terminal so password prompts are visible if your sudo session is not already authenticated.

## CLI

Run the terminal agent:

```bash
python -m linux_troubleshoot_agent "HDMI monitor is not detected"
```

Check how a command will be classified:

```bash
python -m linux_troubleshoot_agent --check-command "journalctl -p 3 -xb"
```

## Safety Model

The agent should run read-only diagnostic commands first, explain what it is checking, rank likely causes from evidence, and ask before making system changes.

It must ask before installing or removing packages, editing configs, modifying services, killing processes, rebooting, or running destructive commands.

Supported command syntax is executed without a shell: argv commands, simple pipelines, and `&&`, `||`, or `;` sequencing. Unsupported shell syntax is rejected by the command runner rather than passed to Bash.

Before a modifying command or maintenance action is approved, the UI shows a plan with risk, backup, rollback, and verification notes. Scans, workflows, approvals, declines, and maintenance actions are recorded in the local memory audit trail.

## Suggested Agent Config Shape

```json
{
  "name": "Local Linux Troubleshooting Agent",
  "description_file": "prompts/description.txt",
  "system_prompt_file": "prompts/system_prompt.txt"
}
```
