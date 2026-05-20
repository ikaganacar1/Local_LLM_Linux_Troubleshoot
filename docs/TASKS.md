# Improvement Tasks

Completed implementation checklist:

- [x] Local API token for browser-originated POST requests.
- [x] Origin/referer checks for protected local APIs.
- [x] Command execution without `shell=True` for supported command syntax.
- [x] Approval plans with risk, backup, rollback, and verification notes.
- [x] Audit trail for scans, workflows, approved commands, declined commands, and maintenance actions.
- [x] Persistent system profile fields learned from scans.
- [x] Guided workflows for display, audio, network, services, packages, boot, storage, and Bluetooth.
- [x] Issue dashboard in the right rail.
- [x] Package-manager-specific issue detection for update and integrity problems.
- [x] llama.cpp model defaults loaded from `/props`.
- [x] Editable LLM parameters with blank values meaning server defaults.
- [x] UI rendering for workflow summaries and safer confirmations.
- [x] Optional `LTA_UI_PASSWORD` lock for the local browser console.
- [x] Distro-aware repair plans attached to scan and workflow summaries.
- [x] Per-workflow model prompts for focused subsystem analysis.
- [x] Exportable audit and profile JSON from the GUI.

Follow-up hardening candidates:

- [ ] Optional password management inside the settings dialog.
- [ ] More distro-specific repair plans for Fedora, openSUSE, and Alpine edge cases.
- [ ] One-click copy buttons for suggested diagnostic commands.
- [ ] Import/export of complete chat history.
