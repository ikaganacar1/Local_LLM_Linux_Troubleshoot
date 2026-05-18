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

Follow-up hardening candidates:

- [ ] Optional user-set password before serving the UI.
- [ ] More distro-specific repair plans.
- [ ] Per-workflow model prompts tuned for each subsystem.
- [ ] Exportable audit log view.
