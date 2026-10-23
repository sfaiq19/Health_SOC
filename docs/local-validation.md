# Local validation on 22 October 2026

The implementation was tested on Windows with the VM powered off. These results establish local software behavior, not Wazuh detection, cross-host capture, measured timing or clinical realism.

## Reproduced checks

` .venv\Scripts\python.exe -m pytest -q --tb=short ` passed **78 tests and 6 subtests**. The final full run completed in 45.96 seconds. Tests include actual local HTTP transfers, persisted SQLite workflows, role/care checks, expiry, audit failure, malformed evidence/receipts, Windows junctions, hard links, reset, threshold-size boundaries, protocol evidence shape and source/receiver agreement.

The fresh-environment packaging check reproduced the old missing-backend failure (exit 2 with build isolation disabled) and passed the corrected installation (exit 0). Its logs remain in the local run directory and are not included in the repository. This verifies fresh Windows packaging; Ubuntu execution remains pending.

## Diagnostic end to end run

Command: `.venv\Scripts\python.exe scripts/run-local-validation.py`

Preserved evidence: `$env:USERPROFILE\HealthcareSOCLab\validation\<run-id>`.

| Workflow | Run ID | HTTP receipts | Source audit events | Live acceptance |
|---|---|---:|---:|---|
| Baseline | ca7c9da3-697e-46a1-acb2-b479c8941122 | 35 | 65 | Incomplete |
| S1 | f1822bb0-40f6-4ec7-a1a3-5e790ebc6398 | 38 | 39 | Incomplete |
| S2 | 800c5d00-a10f-4226-a02a-2c0599380622 | 54 | 105 | Incomplete |
| S3 | 6f08cd33-7d33-4aaf-9664-07569193b0b8 | 3 | 5 | Incomplete |

Requests crossed actual Windows loopback sockets. S1 produced six rejected logins followed by a valid clinician login and 30 distinct off-assignment reads. S2 changed 50 real dummy files and stored before/after inventories; restoration subsequently verified all 50 original hashes. S3 delivered 5,000,000 synthetic bytes to an independent local receiver and reconciled size and SHA-256. The baseline exercised all modules, an approved export and one normal login typo.

Each run uses diagnostic timing with sleeps skipped and is explicitly labeled in its manifest. Wazuh archives/alerts, actual packet captures and native rule proof are absent, so every run correctly evaluates as incomplete. Synthetic evidence used in evaluator unit tests is confined to temporary test directories and explicitly stubs the external decoder; it is not included as live lab evidence.

## Review fixes

A fresh independent reviewer identified seven important defects. Regression tests reproduced the hard-link escape, delayed-archive false acceptance, corrupt-PCAPNG false acceptance, wrong-directory FIM matching, insufficient heartbeat state, missing clean-install backend, and malformed nested-evidence crash. Those were addressed, followed by the final green suite. The capture/generator directory conflict was resolved using the `RUN/generated` staging directory. Additional tests cover false receiver receipts, storage failure and actual server-policy discovery for mitigation runs.

Native rule loading/correlation, FIM coverage, dashboard import/Vega rendering, cross-host packet visibility/loss, resource stability, measured timing, real SIEM query exports, final report layout and second-student rebuild remain pending. The prepared dashboard is a candidate object file, not an observed screenshot. No production-security, compliance or clinical-safety conclusion follows from these tests.
