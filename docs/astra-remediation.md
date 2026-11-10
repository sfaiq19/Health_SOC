# Astra finding remediation — 25 October 2026

Review baseline: `922e58edc8daf20e4a9da028357cf44f04b0a006`.
Branch: `codex/astra-review-fixes`. The existing checkout was clean on main; fixes use a dedicated branch in this checkout. No VM, external service, or native acceptance state is changed by this repair.

Scope is the nine findings in the resumed Astra review. Implement with failing regression tests first, then focused checks and the full suite. Keep native acceptance separate.

## Repair checklist

- [x] 1. Persist workload intent and reconcile operations, receipts, outcomes and baseline coverage.
- [x] 2. Enforce source/receipt/run time bounds and collection endpoint provenance.
- [x] 3. Verify full expected native per-event sequences, including post-burst classification.
- [x] 4. Reject early false positives, missing results and incomplete native transcripts.
- [x] 5. Bind native proof to effective configuration and an unchanged rules snapshot.
- [x] 6. Return structured invalid metrics for malformed receipt data.
- [x] 7. Revalidate audit links at the write boundary and fail closed.
- [x] 8. Reject oversized telemetry integers with HTTP 400.
- [x] 9. Publish already complete partial downloads only after exact hash verification.

Checked boxes mean implemented and locally regression-tested. They do not certify native Wazuh behavior.

## Decisions and verification

Ruling: retain the existing checkout and create a dedicated repair branch rather than another VM or worktree. This keeps the user's runnable project and virtual environment together; changes remain reviewable through Git.

Ruling: bind a loaded candidate with a content-derived revision in the existing 110001 classifier description, challenged in its own fresh logtest session. Hash the installed config/executable/rules before and after testing. This avoids claiming that the `--rules` filename determines what the existing Wazuh sandbox loaded. The marker affects descriptive metadata only; no rule consumes scenario labels or run IDs. Cost if wrong: the actual native challenge must fail and keep acceptance open.

Ruling: full standalone baseline acceptance requires at least the planned ten-minute holdout, document activity and approved exports. Short development or document-paused background runs remain available but cannot substitute for baseline acceptance. Legacy manifests/proofs lack sufficient intent/provenance and must be regenerated.

RED evidence: all three audit/numeric/download regressions failed on the reviewed code; the four native expectation/transcript/revision/snapshot regressions failed; evaluator failures reproduced false completeness, out-of-window acceptance and malformed-receipt crashes; CLI returned 1 without metrics and workload intent was absent. GREEN: API/audit/download group 21 passed; native/evaluator group 28 passed; evaluator/CLI/workload/native group 30 passed before adding the later wrapper/coverage checks.

Fresh actual loopback validation: `C:\Users\YOUR_USERNAME\HealthcareSOCLab\validation\20261025T135451961190Z`. Baseline and S1/S2/S3 generated, all remained incomplete for live acceptance, all 50 documents restored and verified. There were no unexpected receipt/operation reconciliation errors; the listed gaps were diagnostic timing and deliberately absent native evidence.

## Final verification — 26 October 2026

The fresh whole-change Astra review found three important follow-up gaps and no critical/minor findings. All three were addressed in the agreed single repair pass:

- Required response keys and types: missing document hashes/results, malformed digest/UUID/byte fields now fail closed. `test_document_response_results_cannot_be_omitted` and `test_response_result_fields_require_correct_types` failed first, then passed.
- Authoritative native expectations and provenance: the driver and evaluator now share `native_validation.py`; proof-provided expectations cannot replace that contract. The snapshot must identify rules/config/executable roles using absolute paths and SHA-256 values, including the exact collected rules hash. `test_native_proof_cannot_supply_its_own_expectations` and `test_malformed_native_snapshot_cannot_pass` failed first, then passed.
- Scheduled timing: each matched operation must occur no earlier than its planned elapsed time, allowing the documented one-second clock tolerance and delayed execution. `test_idle_tail_cannot_disguise_compressed_baseline` failed first, then passed.

Final full command: `.venv\Scripts\python.exe -m pytest -q --tb=short` → **106 passed, 6 subtests passed in 106.85 seconds**. Focused evaluator/native/CLI group: **38 passed**. Python compile checks and `git diff --check` passed. No second review was substituted for the failing/passing regressions after the single fix pass.

Fresh final actual HTTP validation: `C:\Users\YOUR_USERNAME\HealthcareSOCLab\validation\20261025T192024390802Z` (UTC folder timestamp; 26 October in Asia/Karachi). All four generators succeeded, with **130 HTTP receipts and 214 source audit events**. All 50 documents were restored and verified. The evaluator correctly returned incomplete for every run. Schedule warnings are expected in diagnostic mode because sleeps are skipped; native archives/alerts/captures/proof are deliberately absent. No receipt identity, result or operation-count disagreement was observed.

Final review rulings: actual loaded Wazuh behavior, native acceptance, cross-host capture, dashboard rendering and measured trials remain open under the existing split workflow; local wrapper tests and the source-function characterization do not certify those behaviors. There are no deferred minor findings from this repair review. The cost of this boundary is that native integration adjustments may still be necessary before the project can be submitted as a verified SOC lab.

All nine original findings and the three review follow-ups are addressed in implemented code with passing local regression coverage. No VM/service installation, merge or publication is included in this remediation.

Native Wazuh execution, actual loaded-rule behavior, cross-host capture, dashboard import and final measured trials remain pending regardless of local test outcomes.

## Evaluator Re-verification & Release Gate — 10 November 2026

The stale 26 October blanket closure statement regarding evaluator completeness is hereby superseded by the re-verification results of Tasks A1–A4 on branch `codex/astra-review-fixes`.

### Hardened Evaluator Controls
1. **Application-to-FIM/Inventory Digest Corroboration (Task A1):** S2 evaluation strictly joins application update digests (`app.jsonl`, `archives.jsonl`, PUT receipts) against file inventory before/after hashes and FIM syscheck digests. Contradictory application hashes prevent FIM correlation (`fim_correlated_files == 0`) and flag `Application document update digests disagree with inventory or FIM evidence`.
2. **Actionable Alert Reconciliation (Task A2):** Actionable alerts (e.g., rule 110201) must reconcile agent identity (`hospital-win`) and source event `request_id`. Tampered agent names or mismatched request IDs fail closed (`observed_rules == []`, `attack_detection_passed == False`, `alert_latencies_s == []`, issue: `Actionable alert does not reconcile with its source event`).
3. **Lab Result Order Binding (Task A3):** Baseline lab results are strictly paired one-to-one with preceding successful lab orders matching the canonical `order_id` in the same run. Swapped, reused, missing, or cross-run order IDs fail closed with `Laboratory result does not reconcile with its preceding planned order`.
4. **CLI Contradictory Bundle Evaluation (Task A4):** `tests/test_cli.py` includes `test_cli_contradictory_evidence_bundle_writes_incomplete_metrics_and_returns_nonzero`, verifying that CLI evaluation of a mutated S2 bundle writes `metrics.json` with `status: incomplete`, `fim_correlated_files: 0`, and issues containing `Application document update digests disagree with inventory or FIM evidence`, exiting nonzero.

### External Probe Replay Results
Replayed Astra's independent adversarial probes from `$env:USERPROFILE\HealthcareSOCLab\reviews\2026-11-10-antigravity-reverification\independent-probes.py` (copied from the read-only `2026-10-26-astra-verification` directory). Results persisted to `C:\Users\YOUR_USERNAME\HealthcareSOCLab\reviews\2026-11-10-antigravity-reverification\independent-results.json`:
- `positive-baseline`: `status == 'complete'`, `issues == []`
- `positive-s2`: `status == 'complete'`, `issues == []`, `fim_correlated_files == 50`
- `receipt-result-object`: `status == 'complete'` (valid control: `/health` receipt with `result == {}`)
- `s2-update-digests-disagree-inventory-fim`: changed from `complete` (`fim_correlated_files: 50`) to `incomplete` (`fim_correlated_files: 0`) with issues `["Application document update digests disagree with inventory or FIM evidence", "FIM digest corroboration incomplete; manual path/time fallback is not auto-accepted"]`
- `wrong-actionable-alert-agent`: changed from `complete` (`observed_rules: ["110201"]`) to `incomplete` (`observed_rules: []`, `attack_detection_passed: false`, `alert_latencies_s: []`) with issues `["Actionable alert does not reconcile with its source event", "Expected detection families missing, or actionable baseline incidents observed"]`
- `wrong-actionable-alert-request`: changed from `complete` (`observed_rules: ["110201"]`) to `incomplete` (`observed_rules: []`, `attack_detection_passed: false`, `alert_latencies_s: []`) with issues `["Actionable alert does not reconcile with its source event", "Expected detection families missing, or actionable baseline incidents observed"]`
- `unrelated-lab-result-orders`: changed from `complete` to `incomplete` with issue `["Laboratory result does not reconcile with its preceding planned order"]`

### Test Suite Execution
- Focused evaluator & CLI suite: `rtk proxy .venv\Scripts\python.exe -m pytest tests/test_evaluation.py tests/test_cli.py -q --tb=short` → **58 passed in 16.20s**.
- Full test suite: `rtk proxy .venv\Scripts\python.exe -m pytest -q --tb=short` → **132 passed, 6 subtests passed in 76.47s (0:01:16)**.
- Git diff hygiene: `rtk proxy git diff --check` passed cleanly.

### Fresh HTTP Validation Run
Executed `rtk proxy .venv\Scripts\python.exe scripts/run-local-validation.py`.
Evidence preserved at: `C:\Users\YOUR_USERNAME\HealthcareSOCLab\validation\20261110T161056504321Z`.

| Workflow | Run ID | HTTP receipts | Source audit events | Live acceptance |
|---|---|---:|---:|---|
| Baseline | `da733281-60e4-45ea-bd04-d4873d0da303` | 35 | 65 | Incomplete |
| S1 | `2d3070bb-1d0a-4130-bb08-e793fcfbb67e` | 38 | 39 | Incomplete |
| S2 | `8629888b-3e5e-4670-9bb0-2007c2f70d4a` | 54 | 105 | Incomplete |
| S3 | `5e45f48f-2547-4b34-befb-b31546022712` | 3 | 5 | Incomplete |
| **Total** | | **130** | **214** | |

- **Restoration:** All 50 seed documents restored and verified (`restored: 50, verified: true`).
- **Live Acceptance:** All four workflows evaluate as `incomplete` for live acceptance due to diagnostic timing and absent native Wazuh/cross-host captures.
- **Integrity Checks Confirmed:** Neither `Laboratory result does not reconcile with its preceding planned order` nor `Application document update digests disagree with inventory or FIM evidence` appeared in any scenario's `metrics.json`. Baseline has only diagnostic timing/duration and missing native evidence; S2 only lacks native evidence/captures.
