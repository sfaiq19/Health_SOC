# Healthcare SOC remaining implementation plan for Antigravity (Gemini)

> **Execution instruction for Gemini:** Open the existing Healthcare SOC repository and work through the unchecked items below. Use the executing-plans workflow if available, or track the checkboxes directly. Start with A1–A3 on Windows with the VM off. Then follow Tasks 1–9 using the existing implementation. At every resumption read the latest ledger, identify the last evidenced gate, and start at the first open dependency.

**Goal.** Deliver a reproducible synthetic Healthcare SOC with three demonstrated attacks, independent packet and Wazuh evidence, defensible metrics, and an evidence-based report.

**Starting point, 10 November 2026.** Windows checkout `C:\Users\YOUR_USERNAME\OneDrive\Desktop\SOC Project`, main at `4b70505`. The API, clients, receiver, XML rules, native test driver, evaluator, dashboard candidate and operator scripts already exist. Last recorded local suite passed 106 tests and 6 subtests. Four loopback diagnostic runs produced 130 HTTP receipts, 214 audit events and verified restoration of 50 documents. All four evaluated incomplete for live acceptance. The installer was still a partial download. Recheck the actual working tree and runtime at startup.

**Read first.** [Design](../specs/2026-10-22-healthcare-soc-design.md), [original nine-task plan and scoring matrix](2026-10-22-healthcare-soc.md), [operator commands](../../operator-handoff.md), [implementation ledger](../../implementation-progress.md), [assignment](../../../Project.docx). The later independent review at `%USERPROFILE%\HealthcareSOCLab\reviews\2026-10-26-astra-verification\review.md` supersedes the repair checklist's claim of complete reconciliation. The portable reproductions below also work when that private review folder is unavailable.

**Execution constraints.** Use synthetic data and the dedicated lab only. Keep the runtime outside OneDrive at `%USERPROFILE%\HealthcareSOCLab`, with hospital files in its `hospital` child. Preserve existing VM files, historical runs and unrelated services. Use fresh output directories. Keep credentials, private handoff ZIPs and raw credential-bearing captures private. Run coding and local tests with the VM off. For live sessions, prepare commands first, release the agent IDE's memory, run the VM with the small Windows hospital process, then shut down the lab VM before reopening the IDE to inspect evidence. Identify the specific operator action when an interactive installer, administrator login or second student is required.

## A. Close the three evaluator defects first

Use the current public evaluation entry point `evaluate_run(manifest, artifacts_dir)` and CLI `python -m hospital_soc evaluate --run-dir DIRECTORY`. Extend `tests/test_evaluation.py` and its existing `tests/evidence_fixtures.py` seam. Keep the raw source audit, receipt, Wazuh archive, alert, filesystem inventory and FIM observation distinct. Use realistic positive fixtures throughout. For each adversarial mutation first reproduce a false pass, then require a specific issue and a non-complete verdict. A positive fixture must still complete. Missing evidence should remain distinguishable from a genuine observed zero.

### A1. Join S2 application hashes to independent file evidence (P1)

- [x] Build a positive S2 bundle with 50 successful PUT receipts, terminal `document_update` events and corresponding inventory/FIM digests. Mutate one document's receipt and source together to two different, valid SHA-256 values. Update corresponding synthetic archive/alert copies to preserve their internal consistency. Leave both inventories and native FIM unchanged. Repeat with all 50 mutated. The old evaluator accepts this.
- [x] In `src/hospital_soc/evaluate.py`, use the existing receipt-to-terminal-source validation in `evidence_contract.py`. For each expected document D001–D050, join its unique successful update to its request, document ID, before/after inventory entries, and FIM event under the exact dummy root on hospital-win in the eligible time window. Require the same before/after digest pair throughout and a genuine change. Guard against missing or duplicate application updates and contradictory observations. Count a corroborated file once only after the complete match.
- [x] Assert that the single-document mutation reduces corroboration below 50, the all-document mutation cannot pass, and an untouched fixture has 50/50. Preserve the checks for wrong directories, wrong agent, timing and missing FIM digests.

### A2. Require actionable alerts to match the endpoint and request (P2)

- [x] Update the positive S2 fixture's actionable alert with `agent.name = hospital-win`. Independently mutate that name, remove it, replace `data.request_id` with an unrelated canonical UUID, and omit the request ID. Preserve event ID, run ID, rule ID, timestamps, actor and action in each test.
- [x] In `src/hospital_soc/evaluate.py`, resolve the source event **before** counting an actionable rule as observed or computing its latency. Require the expected endpoint, same run, event and request identities, plus existing actor/action/outcome/time checks. Reject inconsistent target-run alerts with an explicit issue, including when a valid alert is also present. An invalid alert alone must not satisfy the expected family or yield a successful detection metric.
- [x] Test a valid alert, unrelated background-run alerts, and a mixed valid/invalid case. Keep native syscheck evidence on its separate path/time/hash contract: it carries no application request ID.

### A3. Bind every baseline lab result to the intended order (P2)

- [x] Read `src/hospital_soc/workload.py`, `clinical.py` and `evidence_contract.py` together. The generator creates an order and posts its returned ID with the result. The order response contains `order_id`; the result response contains `result_id`; the terminal result audit carries both. Update the positive fixture to preserve that actual relationship for every planned pair.
- [x] During planned-operation reconciliation, associate the successful order receipt and matching terminal source event with the corresponding following planned result. Require a canonical order ID, a result event referencing that exact ID, a matching result receipt ID, and one-to-one pairing in the same run. Use planned pairing and observed request chronology. Membership in a set of all order IDs alone would accept a swapped pair. Preserve the current HTTP response shape.
- [x] Cover missing IDs, an unknown order, an order from another run, two valid order IDs swapped across results, a reused order, and the correct multiple-pair baseline. Assert an explicit issue for every mismatch.

### A4. Release gate for the evaluator

From the Windows checkout use the existing Python virtual environment. Prefix shell invocations with `rtk` on this host per workspace instructions.

```powershell
rtk proxy .venv\Scripts\python.exe -m pytest tests/test_evaluation.py tests/test_cli.py -q --tb=short
rtk proxy .venv\Scripts\python.exe -m pytest -q --tb=short
rtk proxy .venv\Scripts\python.exe scripts/run-local-validation.py
rtk proxy git diff --check
```

- [x] Exercise the CLI on a contradictory bundle and inspect the persisted metrics and nonzero exit. Replay Astra's mutations against fresh output. If using the external `independent-probes.py`, copy it to a new private review directory before running it because it writes beside itself. Record actual statuses and changed counts, including the valid controls.
- [x] In the fresh real HTTP run, confirm baseline and S1/S2/S3 generated, all 50 seed hashes restored, and no unexpected order/result or application/inventory discrepancy. Diagnostic timing and missing native evidence should still prevent live completion.
- [x] Record actual test results and evidence paths in `docs/astra-remediation.md`, `docs/local-validation.md` and `docs/implementation-progress.md`. Retain the original failed examples and supersede the stale blanket closure statement with a dated result.

## B. Finish the nine lab tasks in dependency order

Use [the operator handoff](../../operator-handoff.md) for the complete Windows/Ubuntu command sequences and private configuration transfer. The following are the remaining deliverables and pass conditions. Tasks 3 and 4 share Task 2 as their prerequisite. Confirm collection with a small smoke run before spending 30 minutes on calibration.

### Task 1. Bring up the dedicated lab

- [x] Run `scripts/check-environment.ps1` and the repository preflight. Record current free RAM/disk, administrator availability, VMware version, running VMs, interface assignments and subnet conflicts. Resume the existing download with `.venv\Scripts\python.exe -u scripts\download-ubuntu.py` using one downloader. Require the final ISO and matching checksum record `ubuntu-verification.json`.
- [ ] Open the prepared `vm\Healthcare-SOC.vmx` under the private runtime. Use 4 vCPUs, 8192 MiB RAM and its 60 GiB virtual disk. Install Ubuntu Server 24.04, configure dedicated host-only networking with Windows 10.77.0.1 and guest 10.77.0.10/24. Temporary installation NAT must be disconnected for measurement. Record the actual interface and SSH fingerprint.
- [ ] Install matching Wazuh 4.14.x components supported by the checked-in driver and matching signed Windows agent using official instructions for the selected patch. Record versions and hashes. Verify manager/indexer/dashboard service health, authenticated dashboard access, and agent `hospital-win` connected to the manager. Install dumpcap/tshark and test capture permissions. Scope Windows inbound TCP 8080 to the guest and lab interface.
- [ ] Preserve a captured VM-to-host smoke request, measured clock offset ≤1 s, and 15 minutes of CPU, memory, swap, disk and service stability observations. If host resources prevent a stable run, preserve readings and resume on a suitable lab host. Update `docs/environment.md`.

### Task 2. Verify the hospital across hosts

- [ ] Follow the operator handoff's Windows setup, seed and configuration steps. Check the runtime contains 200 synthetic patients, 10 device identities and 50 existing dummy documents. Prepare and copy the private guest handoff with the supplied scripts, restrict its secret file permissions and run `scripts/setup-linux.sh` on Ubuntu.
- [ ] Start Windows service with `.venv\Scripts\python.exe -m hospital_soc --config config\lab.local.json serve`. From the guest exercise login success/failure, assigned and unassigned record access, order and result creation, device telemetry/heartbeat, document inventory and a bounded update. Compare HTTP outcomes and request IDs against Windows audit events, SQLite rows and file effects. Restore smoke-test changes before measured runs. Preserve receipts and evidence of the actual network exchange.

### Task 3. Establish normal traffic and packet capture

- [ ] Identify the host-only device using `ip -4 addr` and `dumpcap -D`. Start the approved and unapproved registered receivers on guest ports 9081 and 9080. Start `bash scripts/capture.sh "$IFACE" "$RUN"` in its own terminal. Define IFACE from the inspection and RUN as a fresh private evidence path.
- [ ] With collection confirmed in Task 4, run `.venv/bin/python -m hospital_soc --config config/client.local.json baseline --minutes 30 --seed 101 --output "$RUN/generated"`. Include approved exports and document activity. Stop capture after the drain, bring generated manifest to the evidence root and run `bash scripts/export-packets.sh "$RUN"`.
- [ ] Record rates by workflow, actor, UTC window, capture drops and representative frame numbers for authentication, record access, laboratory and device activity. Establish the calibration envelope for tuning. Reserve three independent 10-minute holdouts for Task 8.

### Task 4. Verify Wazuh ingestion, FIM and recovery

- [ ] Render `siem/agent-localfile.xml` and `siem/agent-fim.xml` for the real Windows hospital runtime. Merge into the existing agent configuration and restart. Follow `siem/manager-archives.md` to enable JSON archives and indexing. Confirm initial FIM inventory of the pre-existing dummy directory, then create archive/alert data views and inspect field mappings, including numeric bytes and UTC timestamps.
- [ ] Send a known small run. Join every unique source event ID to its archived event under hospital-win within 120 seconds and count duplicates separately. Mutate and restore one known file. Save the native syscheck event, actual built-in rule ID, full path and digests.
- [ ] Interrupt and restore agent collection for a small labelled test window. Record which events arrived or stayed missing, delay, and heartbeat freshness. Once the dashboard exists, demonstrate stale status after 90 seconds and recovery on resumed traffic. Save raw observations. Only accept collection after benign and suspicious records are searchable and loss is visible.

### Task 5. Prove native rules and S1 account misuse

- [ ] Install `siem/healthcare_rules.xml` in the enabled manager ruleset. If edited, stamp it with `.venv/bin/python scripts/verify-native-rules.py --stamp-rules siem/healthcare_rules.xml` before installing. Reload the manager, inspect errors, and run `sudo .venv/bin/python scripts/verify-native-rules.py --output NEW_PRIVATE_PROOF_DIRECTORY` on Ubuntu. Retain all transcripts, installed XML, binary/config/rule hashes, exact version and loaded-revision result. Require the challenge plus all 25 controls to pass in the real engine. Repeat after rule changes.
- [ ] In observe mode, run `bash scripts/run-lab-scenario.sh s1 "$IFACE" "$RUN"` with a fresh RUN. Verify six 401 failures over 30 s, known successful clinician login, and 30 distinct unassigned record reads over 45 s. Confirm rule families 110101, 110102 and 110103, with actual source/request identity, timestamps, distinct patient count and matching packets.
- [ ] Execute the enforcement comparison separately. Confirm unassigned reads receive 403 and return no record content while legitimate assigned access still works. Keep normal comparison traffic on distinct actors and run IDs.

### Task 6. Prove S2 file changes and recovery

- [ ] Quiesce benign document edits while keeping other benign modules available. With the hospital stopped, use the bounded reset procedure in `scripts/reset-lab.ps1`, restart, wait for FIM stabilization and preserve the initial inventory. Use a fresh RUN and invoke the same scenario wrapper with `s2`.
- [ ] Verify exactly 50 manifest-listed files changed at one per second, rule 110201 fired, all 50 application digest pairs agree with independent inventories and native FIM from the correct endpoint/directory, and packets support the requests. Retain 19/20/21 boundary, failed-write and low-rate control results. Unexpected concurrent writes require a new attempt.
- [ ] Restore all 50 original hashes, retaining the reset receipt and post-restore inventory outside the measured attack window. If native digests are unavailable, record the missing fields. Keep automated corroboration incomplete and record any manual attribution separately.

### Task 7. Prove S3 export and enforcement

- [ ] In observe mode use the scenario wrapper with `s3` in a fresh RUN. Transfer exactly 5,000,000 synthetic bytes to the registered business-unapproved receiver. Join sender completion, receiver receipt and received binary by transfer ID, exact bytes and SHA-256. Verify rule 110302 and capture the outbound connection.
- [ ] Exercise approved 250 KB and 5 MB controls, a small unapproved transfer (110301), and native boundary cases at 999,999 / 1,000,000 / 1,000,001 bytes. A failed transfer must produce no completed-export event. Record observed rule precedence and packet frame references.
- [ ] In enforce mode rerun S3 using fresh evidence. Verify denial before network transmission, unchanged receiver inventory, no new transfer bytes, and continued operation of the approved route. Record this as mitigation evidence with its own expected outcomes. If the evaluator only supports observe-mode positives, preserve that limitation explicitly.

### Task 8. Run the measured evaluation and validate the dashboard

- [ ] Freeze the tested installed rule revision after calibration. On this revision collect **three independent 10-minute benign holdouts and three observe-mode repetitions of each attack** (nine attack attempts). Record each attempted run, including failures, with an opaque UUID, seed, policy mode and fresh directory. Keep mitigation reruns separate. If tuning changes rules, retain the old results, re-run native validation and repeat the measured comparison on the new revision.
- [ ] Before each subsequent measured run reconcile the previous run's final manager event, record the drain and enforce ≥65 seconds of quiet. Watch for late prior events. During attacks run benign comparison traffic under separate identities and run IDs. The scenario wrapper starts its own receivers and capture, so avoid port conflicts. Its 30-second post-run wait does not establish Wazuh ingestion.
- [ ] For each run assemble `manifest.json`, `app.jsonl`, `archives.jsonl`, `alerts.jsonl`, `traffic.pcapng`, `frames.csv`, `observations.json`, matching `healthcare_rules.xml` and `native-rule-tests.json`. Include S2 before/after inventories and restore proof, or S3 `receiver.jsonl` and received binary, as applicable. Preserve command output, raw transcripts, capture statistics and clock/visibility observations. Use the handoff's observation schema and UTC bounds. Missing evidence stays missing.
- [ ] Run `.venv/bin/python -m hospital_soc evaluate --run-dir "$RUN"` on finalized bundles with real tshark available. Save exit code and metrics. Inspect representative packets and compare flows, frame/time bounds and payload size against app/receiver evidence. Capture drops, wrong interfaces, ID mismatch and incomplete coverage must be visible in the result.
- [ ] Execute Q1–Q6 in `siem/queries.md` using real data views and exact UTC/run filters. Save query text, time bounds, exports and screenshots. Import `siem/dashboard.ndjson`; verify all eight panels against query results, 10-second refresh, numeric aggregations and stale/unknown/recovered health states. Export the working dashboard from Wazuh. Check native agent connection state separately.
- [ ] Produce one row per attempt with expected/observed families, counts, rule revision, coverage, FIM/transfer checks, alert latency, first index visibility, drops, benign incidents and recovery. Targets: 9/9 positive runs, 100% unique collection within 120 s, S2 50/50, exact S3 integrity, alert latency ≤30 s, analyst visibility ≤60 s and zero deduplicated actionable incidents across the 30 holdout minutes. Report actual values, denominators and missing observations. If reporting precision/recall, use matched incidents consistently and show undefined denominators as N/A.

### Task 9. Finish the submission and independent reproduction

- [ ] Use `Project.docx`, the original scoring matrix, `docs/protocols.md`, `docs/playbooks.md` and `docs/demo.md`. Assemble an editable report with the actual topology, software versions, simplified hospital protocols and roles, three attack timelines, annotated packet frames, native rule/search/dashboard evidence, measured results, response and restoration. State observed failures and the limits of the small synthetic sample.
- [ ] Link figures and per-run rows to preserved evidence IDs. Redact credentials, tokens and private paths in shareable materials. Render the final DOCX to PDF and inspect all pages, figures, captions and tables. Rehearse the demo against the documented reset and recovery path.
- [ ] Have a second student follow the clean setup/reset instructions and run the cases. Record their inputs, versions, evidence paths, deviations and any required fixes. After a fix, repeat the affected step and keep both records. Mark independent reproduction complete only when that person has done it.
- [ ] Update the ledger for each of the nine gates with date, software/rule revision, commands, observed results, evidence links and remaining blockers. Deliver the report, dashboard export, six query results, scenario evidence index, run metrics and rebuild instructions.

**Handoff at a blocker.** Record the last successful step, exact error or missing input, evidence path, single next operator action and exact command to resume. Continue independent offline work where possible. Administrator login, guest installer interaction and independent student reproduction are explicit human handoffs. Keep the ledger distinction between implemented code, passing local tests, observed live behavior and accepted measured runs.
