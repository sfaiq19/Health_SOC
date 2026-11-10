# Latest local validation — 10 November 2026

The stale 26 October blanket closure statement is superseded by this 10 November 2026 re-verification on `codex/astra-review-fixes`.
Following the evaluator hardening passes for Tasks A1–A4 (joining application document updates to FIM/inventory digests, reconciling actionable alert agent and request identities, enforcing strict 1:1 order-to-result binding for lab workflows, and verifying CLI handling of contradictory evidence), the test suite passes **132 tests and 6 subtests in 76.47 seconds** (focused evaluator & CLI suite: **58 passed in 16.20s**).

The fresh real HTTP diagnostic run is at `C:\Users\YOUR_USERNAME\HealthcareSOCLab\validation\20261110T161056504321Z`: 130 receipts, 214 source audit events, baseline and all three scenarios generated, and all 50 documents restored and verified (`restored: 50, verified: true`). Every evaluator result correctly remains `incomplete` because timing is diagnostic and native Wazuh/cross-host capture evidence is absent. Neither `Laboratory result does not reconcile with its preceding planned order` nor `Application document update digests disagree with inventory or FIM evidence` appears in any scenario's `metrics.json`.

| Workflow | Run ID | HTTP receipts | Source audit events | Live acceptance |
|---|---|---:|---:|---|
| Baseline | `da733281-60e4-45ea-bd04-d4873d0da303` | 35 | 65 | Incomplete |
| S1 | `2d3070bb-1d0a-4130-bb08-e793fcfbb67e` | 38 | 39 | Incomplete |
| S2 | `8629888b-3e5e-4670-9bb0-2007c2f70d4a` | 54 | 105 | Incomplete |
| S3 | `5e45f48f-2547-4b34-befb-b31546022712` | 3 | 5 | Incomplete |

Astra's external adversarial probes were re-executed from `$env:USERPROFILE\HealthcareSOCLab\reviews\2026-11-10-antigravity-reverification\independent-probes.py` (copied without modifying the original `2026-10-26-astra-verification` directory). Results at `C:\Users\YOUR_USERNAME\HealthcareSOCLab\reviews\2026-11-10-antigravity-reverification\independent-results.json` confirmed that all former false passes now fail closed (`s2-update-digests-disagree-inventory-fim`, `wrong-actionable-alert-agent`, `wrong-actionable-alert-request`, `unrelated-lab-result-orders` all evaluate as `incomplete`), while positive controls (`positive-baseline`, `positive-s2`, `receipt-result-object`) evaluate as `complete`.

CLI contradictory bundle handling was verified by `test_cli_contradictory_evidence_bundle_writes_incomplete_metrics_and_returns_nonzero` in `tests/test_cli.py`: mutating PUT receipts and document update events to conflicting hashes results in exit code nonzero, `fim_correlated_files == 0`, and the expected issue persisted to `metrics.json`.

## Previous validation on 26 October 2026

After the Astra repairs, the full suite passed **106 tests and 6 subtests in 106.85 seconds**. New coverage rejects incomplete workloads, inconsistent/malformed receipts, early/out-of-window activity, missing result fields, false native-proof sequences/provenance, post-start audit links, oversized telemetry integers and completed-partial download failures. See [the repair record](astra-remediation.md) for each finding and the independent review follow-ups.

The fresh real HTTP diagnostic run is at `C:\Users\YOUR_USERNAME\HealthcareSOCLab\validation\20261025T192024390802Z`: 130 receipts, 214 source audit events, baseline and all three scenarios generated, and all 50 documents restored and verified. Its folder timestamp is UTC. Every evaluator result remains incomplete because timing is diagnostic and native Wazuh/cross-host evidence is absent. These are local software results only.

## Earlier validation on 22 October 2026

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
