# Latest local & live validation — 14 November 2026

## Publication verification — 14 November 2026

An independent final Windows run of `.venv\Scripts\python.exe -m pytest -q --tb=short` passed **196 tests and 6 subtests in 62.48 seconds**, exit 0. Compilation of `src`, `scripts`, and `tests` passed. Both staged and unstaged whitespace checks passed with line-ending advisories only. The publication inventory contained 94 tracked/nonignored-untracked files; all 93 text/DOCX files, including both DOCX XML archives, were checked against all 18 flattened runtime secret values with zero matches. Raw captures, runtime secrets, local configuration, databases, and private lab evidence are excluded from publication. The report SHA-256 remains `30550908e228bd30a6c61bfa0d51ecf82a0ba63fd4d1556bf4458a4da228328a`.

## Independent evidence copy comparison — 14 November 2026

Read-only comparison resolved the seven Ubuntu/Windows `live-revalidation-20261114` hash differences. The canonical finalized Windows submission matches **318/318** manifest hashes; the retained Ubuntu copy matches **311/318** against the identical manifest. Five metrics files differ only by CRLF versus LF plus a terminal newline; two S2 visibility-poll files differ only by CRLF versus LF. All seven parsed JSON documents and their bytes after in-memory line-ending/optional-terminal-newline comparison are identical. No values, timestamps, event IDs, poll measurements or verdicts differ. Both private copies and their manifests remain untouched. See [the evidence copy provenance](../report/evidence-index.md#windows-and-ubuntu-live-evidence-copy-provenance) and `live_revalidation_20261114.copy_provenance` in [the verification record](../report/evidence-verification.json) for all seven paths and both SHA-256 values. Raw hash mismatches on Ubuntu remain explicitly recorded; no historical timing qualification is waived.

## Task 9 packet replay, timing & receipt instrumentation — 14 November 2026

- **Windows `tshark 4.6.9` compatibility replay (`%USERPROFILE%\HealthcareSOCLab\evidence\replay-20261114-tshark469`):** Root-cause analysis across all 18 captures (`measured-20261113/01..18`) showed `0` unexpected differences across all `52,451` CSV data rows; every discrepancy (`2,562` rows) was on pure HTTP response frames (`http.response.code != ""`, `http.request.method == ""`) where Ubuntu `tshark 4.2.2` leaves `http.request.uri` empty and Windows `tshark 4.6.9` populates the reverse-4-tuple matched request URI. Implemented strict reverse-4-tuple equivalence in `src/hospital_soc/packets.py` (`tests/test_packets.py`: 13 tests including tampering rejections and synthetic HTTP PCAPNG checks) and re-evaluated all 18 untouched captures into a separate output directory (`SHA256SUMS.txt` 38/38 verified; `replay-summary.json` SHA-256 `20a21133f5b673ccce0f2572e60dd7180d1b2bd5a7367b6531cf65c03e39e7a5`): **14/14 observe-mode runs (`01..14`) evaluate `complete` (`issues: []`)**; `15..16` remain `incomplete` for expected enforce mitigation review, and `17..18` evaluate `incomplete` under the general observe evaluator due to missing `observations.json`, `native-rule-tests.json`, workload intent, and general S3 expectations while passing their scoped `control-summary.json` checks (`0` packet errors across all 18 runs).
- **Live timing, rollover fix, S2 & UTC query revalidation (`%USERPROFILE%\HealthcareSOCLab\evidence\live-revalidation-20261114`, `318` files, `SHA256SUMS.txt`: `8b41d5e67e7fed85a3566fbfb83e1c79b62fe81caa568552b4e6c17c9a4a6d0c`):**
  - Preserved failed soak `01-soak-15m-replacement` (`c7e19902-a86c-4b0c-806b-d4c8637c3682`, `seed 101`, `08:30:05.359Z–08:45:05.363Z`): `760/760` archived, `0/760` indexed, `6,628` packets (`0` drops), `18` periodic `/health` clock samples (`max 62.51 ms`), `18` `/proc` samples (`0` OOM), `incomplete` (`Index visibility delay unknown or excessive`) on both evaluators due to midnight UTC `wazuh-archives-4.x-2026.11.14` dynamic object mapping on `data.service` from `syscollector` (Filebeat HTTP `400 mapper_parsing_exception`, diagnostics in `failure-diagnostics/`). Remediated by backing up `wazuh-archives-4.x-2026.11.14` (`10,091` docs -> `index-backup-20261114`), pinning `data.service` + 26 hospital string/ID fields as `keyword` in `/etc/filebeat/wazuh-template.json` and `_template/wazuh`, migrating `10,091/10,091` archive docs (`0` failures), updating `wazuh-alerts-4.x-2026.11.14`, and verifying live `event_id` `5404e66b-7b30-42f9-8980-9d52775e4eb6` visibility (`4.972 s` poll-start estimate, `9` polls).
  - Revalidated replacement soak `01-soak-15m-revalidated` (`de22c9fc-82a9-40b0-82c8-35f685c7017f`, `seed 101`, `08:52:01.105Z–09:07:01.110Z`): **`complete`** (`issues: []`) on both Windows (`tshark 4.6.9`) and Ubuntu (`tshark 4.2.2`), `760/760` archived & indexed, `6,574` packets (`0` drops), `17` periodic `/health` clock samples across the run+drain collection window (`14` strictly inside `manifest.started_at..ended_at`, `9.68–61.42 ms`), `17` `/proc` samples (`mem_available_kb` `5,214,276–5,261,976`, `0` swap used, `load1_max 0.52`, `disk_min_gb 30.64`, `0` OOM), `760/760` `per-event-index-visibility.jsonl` entries (`1.828–11.943 s` source-to-index recorded by `run_reval.py` immediately after each `>= 1.0 s` archive-poll query returned), and `3` live `0.5 s`-interval `data.event_id` OpenSearch polls (`5.616 s` / `10` polls, `7.985 s` / `14` polls, `5.389 s` / `9` polls recorded by `visibility_probe.py` at poll-request start via pre-fix `poll_first_index_visibility`, leaving query duration unmeasured).
  - Explicit UTC-bounded `Q2_s1_1` & `Q3_s1_1` (`query-results/`): queried `wazuh-archives-*` for `06-s1-1` (`e4570e23-7c0a-4490-9861-b9f29405b9c3`) with `bool.filter[0].range.timestamp` (`gte: 2026-11-13T21:10:24.110Z`, `lte: 2026-11-13T21:13:42.151Z`): `Q2` `7/7` (`6 login_failure`, `1 login_success`), `Q3` `30/30` unassigned reads across `30` distinct patients (`aggs_unique_patients: 30`), `0` mismatches vs `06-s1-1/app.jsonl`.
  - Three fresh S2 repetitions + 5 timestamped 50/50 `restore-receipts/` (`reset-pre-serve-20261114.json`, `pre-s2-1-reset.json`, `post-s2-1-reset.json`, `post-s2-2-reset.json`, `post-s2-3-reset.json`, `seed 101`):
    - `12-s2-revalidated-1` (`4db0b64a-ba2a-4fb9-9834-2886d9390f8b`, `seed 201`, `09:10:44.802Z–09:11:39.877Z`): **`complete`**, `105/105` archived & indexed, `897` pkts (`0` drops), `110201` (`0.337, 0.984 s`), `50/50` FIM digests, `9` run+drain clock samples (`3` inside workload window, `max 57.27 ms`), `9` `/proc` samples (`0` OOM), `8.769 s` max `~1 s` loop `per-event` visibility, `8.400 s` / `3.136 s` live `m1`/`m2` `0.5 s` poll-start estimates (unmeasured query duration).
    - `13-s2-revalidated-2` (`226eb296-1c7f-43b7-9651-4a9fc19c8720`, `seed 202`, `09:16:18.089Z–09:17:10.400Z`): **`complete`**, `105/105` archived & indexed, `939` pkts (`0` drops), `110201` (`1.913, 0.568 s`), `50/50` FIM digests, `13` run+drain clock samples (`3` inside workload window, `max 21.57 ms`), `13` `/proc` samples (`0` OOM), `7.707 s` max `~1 s` loop `per-event` visibility, `1.560 s` / `2.956 s` live `m1`/`m2` `0.5 s` poll-start estimates.
    - `14-s2-revalidated-3` (`83168e5e-d388-4d56-8852-61174c4907f1`, `seed 203`, `09:22:32.872Z–09:23:25.634Z`): **`complete`**, `105/105` archived & indexed, `933` pkts (`0` drops), `110201` (`0.363, 0.077 s`), `50/50` FIM digests, `13` run+drain clock samples (`3` inside workload window, `max 19.42 ms`), `13` `/proc` samples (`0` OOM), `8.912 s` max `~1 s` loop `per-event` visibility, `2.700 s` / `4.009 s` live `m1`/`m2` `0.5 s` poll-start estimates.
  - **Prospective timing helper & boundary notes (teammate retesting waived):** Prospective timing fixes in `src/hospital_soc/timing.py` (response-completion `first_visible_utc` and `observation_window`) and `scripts/measure-run-timing.py` (concurrent sampling and polling) apply to future runs and do not alter preserved Nov 14 JSONs. Historical `measured-20261113` intervals (`02-calibration-30m`, `03..05` holdouts, `06..08` S1, `09..11` S3, `15..16` enforce, `17..18` S3 controls) retain historical post-run clock bounds (`not` re-run), and Windows `Stop-Service WazuhSvc` / 15-minute `agents_disconnection_time` testing remains unexecuted non-admin scope. Separate clean-VM retesting by other group members has been waived per project scope decision (`docs/task9-signoff.md`).

## Historical superseded pre-revalidation audit snapshot — 14 November 2026

> Historical pre-compatibility / pre-live-revalidation handover snapshot preserved verbatim below; superseded by the compatibility replay (`replay-20261114-tshark469`), November 14 live revalidation (`live-revalidation-20261114`), and updated report QA below.

Fresh full suite after the dashboard port: **170 passed, 6 subtests passed in 132.98 seconds**, exit0. The dashboard regression checks generator/export equality, panel compatibility, Vega sizing and ten-second refresh. A fresh isolated package check reproduced the old backend failure and passed isolated editable installation (return codes2/0).

The [independent evidence audit](../report/evidence-index.md) verifies the 860 listed hashes, all 26 native transcripts, all 150 S2 joins and eleven selected receiver objects. In that initial pre-patch pass, exact Windows tshark replays were incomplete from decoder-dependent CSV differences while isolated nonpacket rechecks reproduced saved results (superseded by `replay-20261114-tshark469`). Similarly, the initial audit noted post-run clock samples, the soak visibility proxy, Q2/Q3 time bounds and missing timestamped restore receipts (subsequently revalidated for `01-soak-15m-revalidated`, `Q2_s1_1`/`Q3_s1_1`, and `12..14-s2-revalidated-*` in `live-revalidation-20261114`).

Initial Task9 report QA (pre-audit DOCX SHA-256 `49380f3f97b03ad6c6013846c32658b53bd8fa744fc343ad96f41dcdb8c9cdaa`, preserved in `HealthcareSOCLab/report-qa-20261114-checked`): `report/Healthcare_SOC_Report.docx` rendered to ten page images and every page was visually inspected after extracting private LibreOffice 25.2.7.2 under `HealthcareSOCLab/report-tools`. After applying the final-audit report clarifications, `scripts/build-report.py` regenerated `report/Healthcare_SOC_Report.docx` (new SHA-256 `30550908e228bd30a6c61bfa0d51ecf82a0ba63fd4d1556bf4458a4da228328a`), re-exported to PDF/PNGs under `HealthcareSOCLab/report-qa-20261114-audited`, and visually verified across all 10 rendered pages (`page-1.png`..`page-10.png`, zero clipping or overflow). Final post-remediation verification recorded **196 passed, 6 subtests passed** on Windows (`pytest -q --tb=short`) and **46 passed** targeted tests on Ubuntu (`tests/test_packets.py`, `tests/test_timing.py`, `tests/test_api.py`, `tests/test_cli.py`).

Repository handoff is prepared on `codex/task9-finalization`, excluding raw evidence, local configuration and runtime files. A scan against eighteen current long runtime-secret values found zero matches, including inside DOCX XML. Contributions and group rehearsal remain in `docs/task9-signoff.md` (teammate clean-VM retesting waived).

Full offline command `rtk proxy .venv\Scripts\python.exe -m pytest -q --tb=short` passed **169 tests and 6 subtests in 59.66 seconds**, exit 0. Compileall for src/scripts passed. Git diff whitespace validation passed with line-ending advisories only.

The fresh real HTTP loopback run is `%USERPROFILE%\HealthcareSOCLab\validation\20261113T185728394552Z` (UTC folder timestamp). All four generators succeeded, producing 130 receipts and 214 audit events. All 50 documents were restored and verified. Every native acceptance result stayed incomplete.

An offline replay of the original November 13 archive through the updated evaluator reconciled 149/149 source/archive IDs and all custom alert families. Windows case normalization now yields **50/50 exact S2 digest corroboration**. All three diagnostic verdicts remain incomplete for missing observations and native proof, cross-version tshark CSV differences, and the missing S3 received object. Aggregate results are private at `%USERPROFILE%\HealthcareSOCLab\handoff\offline-replay-20261113.json`.

## Live native revalidation and measured acceptance campaign (14 November 2026)

Installed-engine schema-3 validation **PASSED 26/26** on Wazuh `v4.14.10` (`%USERPROFILE%\HealthcareSOCLab\evidence\native-rule-proof-20261113T193310Z`; rules XML SHA-256 `8a71944c501ec8a0b15ccb7c910c96e762f71976ad0be1da49512397fb5eb4bb`; `loaded_revision: db7629b4d71476b5d26f0d98cd2e6c80620dd1fec2f1cfc2becb83da19ada6f7`; 65.001–65.002 s expiry gaps across three distinct sessions). Historical schema-2 failure (`native-rule-proof-20261113T121654Z`, 23/26) and interrupted proof run (`native-rule-proof-20261113T191735Z-3b806aa0`) are preserved alongside it.

Measured cross-host runs (`%USERPROFILE%\HealthcareSOCLab\evidence\measured-20261113`, 860 files / 148.51 MiB SHA-256 verified):

| Run | Mode / scenario | Status | Events (arch/src) | Packets (drops) | Visibility (s) | Clock bound (ms) | Observed rules / checks |
|---|---|---|---:|---:|---:|---:|---|
| `01-soak-15m` | `baseline` (15m) | `complete` | 760 / 760 | 6,937 (0) | 1.959 | 262.84 | `[]` |
| `02-calibration-30m` | `baseline` (30m) | `complete` | 1505 / 1505 | 13,787 (0) | 13.806 | 231.70 | `[]`, 15/15 LIS paired, 122 resource samples |
| `03-holdout-1` | `baseline` (10m) | `complete` | 509 / 509 | 4,156 (0) | 15.326 | 247.48 | `[]` (0 FP) |
| `04-holdout-2` | `baseline` (10m) | `complete` | 509 / 509 | 4,299 (0) | 13.279 | 264.25 | `[]` (0 FP) |
| `05-holdout-3` | `baseline` (10m) | `complete` | 509 / 509 | 4,151 (0) | 19.840 | 281.67 | `[]` (0 FP) |
| `06-s1-1` | `scenario / s1` | `complete` | 39 / 39 | 470 (0) | 10.914 | 269.42 | `110101, 110102, 110103` (0.207–1.895 s) |
| `07-s1-2` | `scenario / s1` | `complete` | 39 / 39 | 472 (0) | 10.592 | 322.33 | `110101, 110102, 110103` (0.139–1.951 s) |
| `08-s1-3` | `scenario / s1` | `complete` | 39 / 39 | 470 (0) | 10.962 | 303.30 | `110101, 110102, 110103` (0.119–1.759 s) |
| `09-s3-1` | `scenario / s3` | `complete` | 5 / 5 | 3,654 (0) | 11.900 | 284.58 | `110302` (1.596 s), 5 MB receiver SHA-256 OK |
| `10-s3-2` | `scenario / s3` | `complete` | 5 / 5 | 3,660 (0) | 8.887 | 286.66 | `110302` (1.533 s), 5 MB receiver SHA-256 OK |
| `11-s3-3` | `scenario / s3` | `complete` | 5 / 5 | 3,606 (0) | 11.886 | 273.48 | `110302` (1.428 s), 5 MB receiver SHA-256 OK |
| `12-s2-1` | `scenario / s2` | `complete` | 105 / 105 | 758 (0) | 10.128 | 265.24 | `110201` (0.297–1.926 s), `50` FIM files |
| `13-s2-2` | `scenario / s2` | `complete` | 105 / 105 | 758 (0) | 9.476 | 277.60 | `110201` (0.767–1.258 s), `50` FIM files |
| `14-s2-3` | `scenario / s2` | `complete` | 105 / 105 | 760 (0) | 9.748 | 286.82 | `110201` (0.217–0.739 s), `50` FIM files |
| `15-s1-enforce` | `enforce / s1` | `incomplete` (control) | 39 / 39 | 470 (0) | 11.731 | 256.90 | `110101` only; 6x `401`, 30x `403` blocked reads |
| `16-s3-enforce` | `enforce / s3` | `incomplete` (control) | 4 / 4 | 40 (0) | 11.814 | 266.13 | `[]`; `POST /api/exports` `403`; receiver unchanged |
| `17-s3-approved-5mb` | `control` (5 MB `approved-lab`) | Scoped control pass; general evaluator: `incomplete` | 5 / 5 (arch/src) | 3,687 (0) | — | — | `[]`; receiver `9081` SHA-256 matched; missing obs/native/intent |
| `18-s3-unapproved-250kb` | `control` (250 KB `unapproved-lab`) | Scoped control pass; general evaluator: `incomplete` | 5 / 5 (arch/src) | 316 (0) | — | — | `110301` only; receiver `9080` SHA-256 matched; missing obs/native/intent |

- **SIEM queries & dashboard (`Step 8`):** Reindexed existing `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*` indices after updating `/etc/filebeat/wazuh-template.json` and `_template/wazuh` with `data.bytes_sent: long`, `data.http_status: integer`, and `data.duration_ms: long`. Saved `Q1–Q6` + `Q5_s3_all_runs` JSON/CSV exports and `reconciliation-summary.json` (`11/11` export SHA-256/byte match = `21,750,000` B; `50/50` FIM digest match). Imported `siem/dashboard.ndjson`, patched `panel.version: "7.10.0"` on `healthcare-overview` to avoid OpenSearch Dashboards `is640To720Panel` null dereference on Wazuh `v4.14.10`, added `"autosize": "none"` on `healthcare-health`, enabled 10 s auto-refresh (`now-4h`), visually confirmed all 8 panels in headless Chromium (`FRESH`/`STALE`/`UNKNOWN` + live 10 s transition), and exported `dashboard-exported.ndjson`. Candidate `siem/dashboard.ndjson` in the repo remains unmodified.
- **Interruption & recovery:** Stopping `filebeat` queued heartbeat `4eaf308d` locally in `archives.json` and indexed it `7 s` after restart; stopping `wazuh-manager` queued `cd5cb788` on the Windows agent and delivered it cleanly after manager restart. Non-admin Windows sessions cannot invoke `Stop-Service WazuhSvc` (`Access Denied`), and manager config sets `<agents_disconnection_time>15m</agents_disconnection_time>`. See [revalidation and diagnosis](2026-11-13-native-revalidation.md) and [acceptance ledger](implementation-progress.md).

## Historical validation — 10 November 2026

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
