# Healthcare SOC implementation ledger

Plan: docs/superpowers/plans/2026-10-22-healthcare-soc.md

## Execution status

10 November 2026 host preflight, ISO verification, and offline handoff preparation update:
- **Host Preflight (`scripts/check-environment.ps1` & `hospital_soc.preflight`):** Gathered host facts at `evidence/environment/host-facts.json` and generated `evidence/environment/assessment.json`. Host characteristics: Microsoft Windows 11 Home, 14 logical processors, 15.45 GiB total RAM, 3.05 GiB free RAM, 265.28 GiB available disk space on `C:`, non-admin session, hypervisor present, VMware Workstation `26.0.0 build-25388281`, 0 running VMs (`Total running VMs: 0`). Network verification confirmed zero IP addresses and zero routes in `10.77.0.0/24` (no collision with proposed lab subnet). Assessment status remains conservatively `blocked` (`insufficient_free_ram`, `missing_administrator`, `missing_wazuh_agent_installed`, `unknown_lab_vm_running`, `unknown_lab_network_verified`).
- **Ubuntu 24.04.5 ISO Retrieval & Verification (`scripts/download-ubuntu.py`):** Download resumed from existing partial installer (910 MB) to full 4,080,486,400 bytes (3,891.46 MiB). Verified against Ubuntu official `SHA256SUMS` with SHA-256 `97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8`. Final ISO published at `$env:USERPROFILE\HealthcareSOCLab\installers\ubuntu-24.04.5-live-server-amd64.iso` with verification record `$env:USERPROFILE\HealthcareSOCLab\installers\ubuntu-verification.json`.
- **Windows Hospital Runtime Seed & Agent XML Rendering:** Seeded `$env:USERPROFILE\HealthcareSOCLab\hospital` via `.venv\Scripts\python.exe -m hospital_soc --runtime "$env:USERPROFILE\HealthcareSOCLab\hospital" seed --seed 101`. Runtime verified with `hospital.sqlite` (200 patients, 10 devices), `secrets.json`, `seed-manifest.json`, and 50 dummy documents (`documents\D001.txt` through `documents\D050.txt`). Generated git-ignored `config/lab.local.json` pointing to local runtime root. Rendered `agent-localfile.rendered.xml` and `agent-fim.rendered.xml` into the runtime directory.
- **Private Guest Handoff Archive (`scripts/prepare-handoff.py`):** Built `$env:USERPROFILE\HealthcareSOCLab\hospital\private-handoff.zip` (121,093 bytes, mode 0600) containing the A1–A4 hardened codebase, client local configuration, and disposable runtime secrets for transfer to the guest VM.
- **Native Acceptance Status:** All live VM and Wazuh acceptance gates remain pending as planned. VM boot was not initiated under the low-memory workflow.

10 November 2026 re-verification update: The stale 26 October blanket closure statement is superseded by completion of Tasks A1–A4 on `codex/astra-review-fixes`. Evaluator hardening now strictly binds application document updates to FIM/inventory digests, reconciles actionable alert agent and request identities, enforces 1:1 order-to-result binding for lab workflows, and verifies CLI handling of contradictory evidence.
- **Test execution:** `pytest tests/test_evaluation.py tests/test_cli.py -q --tb=short` → **58 passed in 16.20s**; full suite `pytest -q --tb=short` → **132 passed, 6 subtests passed in 76.47s**.
- **CLI contradictory bundle verification:** `test_cli_contradictory_evidence_bundle_writes_incomplete_metrics_and_returns_nonzero` passes, verifying exit code nonzero, `fim_correlated_files == 0`, and `Application document update digests disagree with inventory or FIM evidence` in `metrics.json`.
- **External probe replay:** `$env:USERPROFILE\HealthcareSOCLab\reviews\2026-11-10-antigravity-reverification\independent-probes.py` replayed against `independent-results.json`: all former false passes (`s2-update-digests-disagree-inventory-fim`, `wrong-actionable-alert-agent`, `wrong-actionable-alert-request`, `unrelated-lab-result-orders`) now fail closed (`incomplete`), while controls (`positive-baseline`, `positive-s2`, `receipt-result-object`) pass (`complete`).
- **Fresh HTTP validation run:** Preserved at `$env:USERPROFILE\HealthcareSOCLab\validation\20261110T161056504321Z`. 130 HTTP receipts, 214 source audit events, baseline and all three scenarios generated, and all 50 document seed hashes restored and verified. All workflows evaluate as `incomplete` for live acceptance (due to diagnostic timing and absent native Wazuh/cross-host captures). Neither `Laboratory result does not reconcile with its preceding planned order` nor `Application document update digests disagree with inventory or FIM evidence` appears in any scenario's `metrics.json`.
- **Workflows:** Baseline (`da733281-60e4-45ea-bd04-d4873d0da303`: 35 receipts, 65 events, Incomplete), S1 (`2d3070bb-1d0a-4130-bb08-e793fcfbb67e`: 38 receipts, 39 events, Incomplete), S2 (`8629888b-3e5e-4670-9bb0-2007c2f70d4a`: 54 receipts, 105 events, Incomplete), S3 (`5e45f48f-2547-4b34-befb-b31546022712`: 3 receipts, 5 events, Incomplete).
- **Native acceptance:** Still pending regardless of local test outcomes. Tasks 1–9 live VM and Wazuh acceptance remain open.

26 October repair update: the nine findings from the resumed Astra review and three follow-up gaps are fixed on `codex/astra-review-fixes`. Final verification: **106 tests and 6 subtests pass**; fresh actual loopback baseline/S1/S2/S3 generated, all 50 documents restored, and every run correctly remains incomplete for live acceptance. See [Astra remediation](astra-remediation.md) for the acceptance contract, RED/GREEN evidence, final review rulings and remaining native gates. This supersedes the earlier local-review readiness statement below. Native acceptance remains pending.

Task 1 live setup remains pending. The local implementation of Tasks 2–8 has been developed under the user-approved split workflow. Task 9 has operator/demo/report guidance; its final evidence-based DOCX and second-student rebuild remain pending. No live SOC acceptance gate has passed.

| Task | Source/local state | Remaining acceptance |
|---|---|---|
| 1 | Measured preflight (10 Nov 2026), VMware 26.0.0, powered-off VM definition, verified Ubuntu 24.04.5 ISO | Installed guest, isolated network (10.77.0.0/24), privileges, Wazuh/agent, clock/capture/stability |
| 2 | Hospital API, seeded runtime ($env:USERPROFILE\HealthcareSOCLab\hospital), rendered XML snippets, private-handoff.zip; local tests pass | Cross-host requests and live agent collection |
| 3 | Baseline scheduler and actual diagnostic loopback workflow | 30-minute calibration, holdouts and captured frames |
| 4 | Agent/FIM snippets, archive instructions | Apply/verify native collection, mappings, inventory, interruption/recovery |
| 5 | S1 requests and candidate XML correlation rules | Native boundary/group tests, real alert/capture results |
| 6 | S2 writes, inventories and checked restoration | Native 50-file FIM corroboration and measured packet evidence |
| 7 | Real bounded transfers and independent receipts | Cross-host S3 capture/alerts and live mitigation evidence |
| 8 | Conservative evaluator, six queries, eight-panel candidate dashboard | Native import/rendering, field verification, executed queries, soak and repeated measured trials |
| 9 | Operator handoff, demo and report structure | Actual report/screenshots, visual QA, second-student reproduction |

Final local validation: 78 tests and 6 subtests pass; the fresh-environment backend failure was reproduced and corrected. A fresh actual HTTP diagnostic baseline/S1/S2/S3 run is preserved under `$env:USERPROFILE\HealthcareSOCLab\validation\<run-id>`; all four generated successfully and all four remain incomplete for live acceptance. All 50 document seed hashes were restored. See docs/local-validation.md.

Ruling: canonical runtime parent is `$env:USERPROFILE\HealthcareSOCLab`, outside OneDrive and packaged-AppData virtualization. The prepared powered-off VM and partial installer were copied there without deleting the old artifacts, and VMX disk/ISO references regenerated against the stable paths. Cost if wrong: old aliases could confuse the operator, so config, setup defaults and handoff explicitly use the new user-profile path.

Ruling: native event fixtures are generated by scripts/verify-native-rules.py rather than many static JSONL files. This preserves opaque identities and exact boundary cases while running the actual engine in isolated sessions. Cost if wrong: engine behavior is still unverified until every case passes in the VM.

Ruling: use computed Vega source-heartbeat freshness rather than title-only last-seen guidance. It has a one-second clock, 90-second boundary and explicit unknown state; native import/rendering remains pending. Cost if wrong: incompatible installed Vega/mappings must block dashboard acceptance, not be treated as a healthy panel.

Ruling: scenario manifests record the policy actually reported by the server, allowing enforcement reruns without stale client-mode expectations. Cost if wrong: a missing/unknown server mode invalidates the run rather than guessing.

Ruling: automated S2 acceptance requires exact canonical document roots plus all native digest matches. If the engine omits digests, retain incomplete status for the design's explicit manual attribution review. Cost if wrong: otherwise legitimate evidence may need human review, but the automated gate is not weakened.

Final review: seven important findings addressed in one fix pass. Hard-link/junction boundaries, late collection/quiet intervals, structural and independently re-exported packets, exact FIM roots, computed heartbeat state, isolated builds and nested evidence validation have regression coverage; final suite green. No minor findings were deferred by the reviewer.

Final: Ruling: the reviewer declined to certify actual Wazuh/group semantics, agent/FIM coverage, native dashboard/mappings/rendering, cross-host capture/loss, full-stack capacity, measured mitigations, final report quality and second-student reproduction. These remain explicit live gates under the split workflow. Production-security/clinical-safety certification is outside this synthetic prototype. Cost if wrong: reporting any of them as complete would overstate the evidence; none is marked complete.

Task 2: local API/CLI suite passed 24 tests. Task 3: workload suite passed three tests including actual loopback HTTP. Tasks 5/6: S1/S2 generator suite passed three tests, including 50 hash-verified local dummy file changes. Task 7: ten sender/receiver tests passed, including real loopback transfers at 999999, 1000000, 1000001 and 5000000 bytes. All are source/local checks; native Wazuh, cross-host captures and full workloads remain unverified.

Ruling: put hospital runtime in `HealthcareSOCLab/hospital`, retaining VM/installers in sibling directories. The previous base directory now contains VM files and correctly fails the seed safety check. Cost if wrong: every agent path and copied client configuration must use the same hospital subdirectory; templates and runbooks must agree.

Ruling: expose an authenticated document-editor hash inventory route so VM clients can collect before/after Windows filesystem observations without a shared drive. Native FIM remains independent corroboration. Cost if wrong: inventory alone is insufficient; 50 native digest matches remain mandatory for automated acceptance.

Ruling: separate implementation dependencies from lab acceptance dependencies. The user approved developing with the VM off, then running full lab sessions with Codex closed. Implement and test locally in task order while retaining every VM/Wazuh/capture acceptance gate as pending. Cost if wrong: integration adjustments may be needed once the VM is available; local tests must never be reported as Wazuh detection or cross-host packet evidence.

The user authorized implementation on 22 October 2026. The design is the binding specification. Work begins in the existing project directory, which was not a Git repository.

Ruling: use one supported hypervisor and an isolated network for the lab. If the selected host cannot provide the specified VM, move it to a suitable group host rather than reducing monitoring coverage. Cost if wrong: network/isolation checks must be revised before live traffic; no equivalence is assumed until verified.

Pre-flight interfaces: Task 1 supplies addresses, runtime roots, versions, endpoint identity, VM and capture. Tasks 2–8 depend on those live resources; source-only readiness is not a substitute. Task 3's approved exports depend on Task 7, as the plan explicitly allows; its baseline gate stays open until those exports are covered. Task 9 requires a second human group member; it cannot be independently certified by this agent.

## Task 1 evidence

Source verification: preflight unit tests pass. Live readiness assessment correctly returns nonzero with blockers. This is not evidence that installation, network capture, or detection works.

10 November 2026 preflight observation record:
- Local preflight re-executed via `scripts/check-environment.ps1` → `evidence/environment/host-facts.json`.
- Gate assessment executed via `hospital_soc.preflight` → `evidence/environment/assessment.json`.
- Host measurements: Microsoft Windows 11 Home, 14 logical processors, 15.45 GiB total RAM, 3.05 GiB free RAM (below 10 GiB allocation guard), 265.28 GiB free disk on `C:`, non-administrator shell, hypervisor present, VMware Workstation `26.0.0 build-25388281`, 0 running VMs.
- Subnet check: zero routes and zero IPs in `10.77.0.0/24` on active host interfaces; no address conflict.
- Assessment status: `blocked` (`insufficient_free_ram`, `missing_administrator`, `missing_wazuh_agent_installed`, `unknown_lab_vm_running`, `unknown_lab_network_verified`).

Ubuntu 24.04.5 installer verification:
- Resumed and completed via `scripts/download-ubuntu.py`.
- Size: 4,080,486,400 bytes; SHA-256: `97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8` matching `https://releases.ubuntu.com/24.04/SHA256SUMS`.
- ISO location: `$env:USERPROFILE\HealthcareSOCLab\installers\ubuntu-24.04.5-live-server-amd64.iso`.
- Receipt record: `$env:USERPROFILE\HealthcareSOCLab\installers\ubuntu-verification.json`.

Offline Windows hospital runtime & handoff preparation (Task 2 prep):
- Hospital runtime seeded at `$env:USERPROFILE\HealthcareSOCLab\hospital` with `--seed 101` (200 patients, 10 devices, 50 dummy documents `D001.txt`..`D050.txt`, `secrets.json`, `seed-manifest.json`).
- `config/lab.local.json` configured with local runtime path (git-ignored).
- Rendered XML snippets: `$env:USERPROFILE\HealthcareSOCLab\hospital\agent-localfile.rendered.xml` and `$env:USERPROFILE\HealthcareSOCLab\hospital\agent-fim.rendered.xml`.
- Private guest handoff archive: `$env:USERPROFILE\HealthcareSOCLab\hospital\private-handoff.zip` (121,093 bytes, mode 0600) prepared via `scripts/prepare-handoff.py`.

Ruling: initialize Git on `implementation/healthcare-soc` in this previously non-repository project directory. There is no main branch or existing source checkout to isolate; preserve the supplied brief and plan in place. Cost if wrong: none to existing Git history because none existed.

Ruling: require 10 GiB currently available RAM before allocating the 8 GiB VM, reserving 2 GiB for headroom. This only guards initial setup; full-stack stability remains mandatory. Cost if wrong: allocation may be deferred conservatively despite possible Windows memory reclamation.

- The local preflight records OS, capacity, privilege, virtualization, network, and tool observations in ignored JSON under `evidence/environment/`.
- Those preparation observations do not establish a running lab or pass Task 1 acceptance; repeat them on the host selected for the lab.
- Reproducible observations: scripts/check-environment.ps1 → evidence/environment/host-facts.json.
- Readiness assessment: python -m hospital_soc.preflight → evidence/environment/assessment.json; nonzero exit indicates prerequisites are unmet, not a passing lab.

## Pending prerequisites

VM preparation scripts define a 4-vCPU, 8-GiB, 60-GiB Ubuntu Server VM. That specification is not evidence of an installed guest or validated lab. Verify the installer, isolated network, Wazuh, agent, clocks, and capture before closing Task 1.

Need sufficient available host memory, the completed verified installer, a verified isolated network, and an administrator session for Windows agent/firewall installation. Do not close unrelated processes, shrink the planned allocation, install another hypervisor, or mark Task 1 complete to bypass these constraints.

The VM's existing VMnet1 connection is a preparation placeholder. It is not the final proposed 10.77.0.0/24 configuration and is not claimed isolated until verified. Configure the dedicated network or change all lab addresses together before starting traffic.

Verification: 8/8 dependency-free unit tests pass with Python 3.12.14 using `PYTHONPATH=src python -m unittest discover -s tests -v`. Both preflight and VM configuration tests were observed failing for missing implementations before their implementations were added. The host assessment remains blocked; no live acceptance result is inferred from unit tests.

Git staging and `git diff --cached --check` succeeded. Commit was attempted but Git has no configured author identity; changes remain staged. No identity was invented and no global Git setting was changed. This does not prevent continuing installation once the host prerequisites are met.

## Checklist

- [x] Read design and plan; inspect actual host and hypervisor inventory.
- [x] Implement conservative, repeatable environment collection and gate assessment.
- [x] Prepare the explicitly requested new powered-off VM definition and verify its disk allocation.
- [x] Complete and verify Ubuntu installer download (SHA-256 verified; receipt at `$env:USERPROFILE\HealthcareSOCLab\installers\ubuntu-verification.json`); guest OS installation pending.
- [ ] Verify a suitable VM, network isolation, memory capacity, and installation privileges.
- [ ] Install/configure Wazuh and agent; establish authenticated dashboard and agent connectivity.
- [ ] Capture cross-host smoke traffic, measure clock offset, and complete stability check.
- [ ] Task 1 accepted with live evidence.
- [ ] Tasks 2–9 implemented and verified in dependency order.
- [x] Implement the local hospital/workload/scenario/receiver/evaluation code and candidate SIEM artifacts.
- [x] Independent code review and regression fix pass; final local suite and end-to-end diagnostic evidence preserved.
- [x] Prepare low-memory operator handoff, capture staging, native-rule test driver, and demo/report guidance.
- [ ] Complete native VM/Wazuh/capture/dashboard evaluation and final submission artifacts.
