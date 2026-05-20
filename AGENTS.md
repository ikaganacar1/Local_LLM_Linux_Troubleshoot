# Repository Guidelines

## Project Structure & Module Organization

This is a Python local Linux troubleshooting agent with a browser GUI and Docker service.

- `src/linux_troubleshoot_agent/`: core package code.
- `src/linux_troubleshoot_agent/web.py`: HTTP API and GUI server.
- `src/linux_troubleshoot_agent/web_assets/index.html`: single-page GUI.
- `src/linux_troubleshoot_agent/safety.py`: command classification rules.
- `src/linux_troubleshoot_agent/shell.py`: safe command runner.
- `src/linux_troubleshoot_agent/system_scan.py`: scans, workflows, and issue detection.
- `prompts/`: system prompt and short agent description.
- `tests/test_regressions.py`: unittest regression suite.
- `docs/TASKS.md`: implemented improvement checklist and follow-up tasks.
- `compose.yaml` and `Dockerfile`: restart-always local service configuration.

## Build, Test, and Development Commands

Run locally:

```bash
PYTHONPATH=src python3 -m linux_troubleshoot_agent.web
```

Run the full test suite:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Check syntax/bytecode compilation:

```bash
python3 -m compileall src tests
```

Build and run the Docker service:

```bash
docker compose up -d --build
```

Verify the GUI:

```bash
curl -I http://127.0.0.1:28765/
```

## Coding Style & Naming Conventions

Use Python 3.13-compatible code, 4-space indentation, type hints where practical, and small functions with explicit return values. Prefer standard-library modules already used in the project. Keep safety-sensitive code simple and auditable. Use `snake_case` for functions, variables, and test names. Frontend code is plain HTML/CSS/JavaScript in `index.html`; keep DOM updates explicit and avoid adding large dependencies.

## Testing Guidelines

Tests use Python `unittest`. Add focused regression tests for every safety, command parsing, scan, or UI API behavior change. Name tests with `test_...` and keep fixtures local to the test. Always run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Commit & Pull Request Guidelines

Commit history uses short imperative summaries, for example `Fix safety review findings` or `Add markdown rendering for LLM answers`. Keep commits scoped to one logical change. PRs should include a short description, test commands run, affected safety/workflow areas, and screenshots or notes for visible GUI changes.

## Security & Configuration Tips

This app can access the host through Docker. Keep the GUI bound to `127.0.0.1`, preserve token/origin checks, and never broaden command auto-permissions without tests. Changes to `safety.py`, `shell.py`, `web.py`, or package update logic require extra review.
