# Healthcare SOC

Synthetic hospital security lab using Wazuh, Wireshark and a Python service. The approved design and nine-task plan are under `docs/superpowers/`.

The installed Wazuh 4.14.10 lab captured all three cross-host scenarios on VMnet4 (`measured-20261113`), resolved `tshark 4.2.2`/`4.6.9` HTTP response-URI equivalence (`replay-20261114-tshark469`), and completed November 14 live revalidation (`live-revalidation-20261114`: replacement 15-minute soak after UTC rollover `data.service` template remediation, explicit UTC-bounded `Q2`/`Q3`, three S2 repetitions, and five timestamped 50/50 restore receipts). Start at the [current gate ledger](docs/implementation-progress.md) and [native revalidation procedure](docs/2026-11-13-native-revalidation.md).

Latest verification (14 November): **196 passing tests and 6 passing subtests** on Windows (plus **46 targeted tests passing** on Ubuntu `tshark 4.2.2`). Preserved native proof schema 3 verifies 26/26. The [independent campaign audit](report/evidence-index.md) records exact run evidence and boundaries. The [technical report](report/Healthcare_SOC_Report.docx), [reference setup guide](docs/clean-rebuild.md), and [Task 9 record](docs/task9-signoff.md) support submission (separate teammate clean-VM retesting waived).

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
