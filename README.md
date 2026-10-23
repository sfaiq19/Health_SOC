# Healthcare SOC

Synthetic hospital security lab using Wazuh, Wireshark and a Python service. The approved design and nine-task plan are under `docs/superpowers/`.

**Current state:** hospital simulator, bounded baseline/three scenarios, independent export receivers and conservative evidence evaluator are implemented locally. Wazuh rules, dashboard saved objects and lab scripts are prepared for native validation. VM setup, Wazuh rule execution, cross-host packet analysis, measured trials, live dashboard import and final report remain pending. See the ledger for actual results; local tests are not live acceptance.

- Environment observations and reproduction: [docs/environment.md](docs/environment.md).
- Task ledger and blockers: [docs/implementation-progress.md](docs/implementation-progress.md).
- Original plan and acceptance gates: [docs/superpowers/plans/2026-10-22-healthcare-soc.md](docs/superpowers/plans/2026-10-22-healthcare-soc.md).

No patient data or production system is involved. Captures and later run evidence must remain distinguishable from unit-test results.

## Development with the VM off

```powershell
.venv\Scripts\python.exe -m pytest -q
.venv\Scripts\python.exe scripts\run-local-validation.py
```

The second command creates a fresh runtime outside OneDrive and runs actual loopback HTTP for baseline/S1/S2/S3 plus verified restoration. Diagnostic sleeps are skipped and native evidence is deliberately absent; the evaluator must report every such run incomplete. Its JSON summary names the preserved evidence directory.

Use [the operator handoff](docs/operator-handoff.md) for first setup and VM runs with Codex closed. It includes the private credential bundle, capture staging layout, real native rule verification, scenario commands and evidence collection. No administrator access is needed for local development.
