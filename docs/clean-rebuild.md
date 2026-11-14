# Clean rebuild and independent reproduction

The November 13 measured campaign used Ubuntu 24.04.5, Wazuh manager/indexer/dashboard/Windows agent 4.14.10, host-only VMnet4 (`10.77.0.10` guest, `10.77.0.1` Windows), guest interface `ens192`, and guest tshark 4.2.2. These are the measured versions, not a claim that arbitrary newer versions behave identically. Use a new runtime and separate VM/disk for an independent rebuild; preserve the original installation and private evidence.

The repository now generates the dashboard compatibility settings saved in the live `measured-20261113/dashboard-exported.ndjson`: every embedded panel has `version: "7.10.0"`, the Vega specification sets `autosize: "none"`, and the dashboard restores `now-4h` to `now` with a running 10,000 ms refresh. `7.10.0` is the saved-panel compatibility version, not the Wazuh package version. Generating NDJSON does not constitute a fresh import/rendering test.

## Installation order

1. Record the checkout revision with `git rev-parse HEAD`, Windows/Ubuntu/Python/package versions and the UTC start time in a new private rebuild record. Start from a fresh checkout/venv and unpopulated runtime. Read [operator setup](operator-handoff.md) for the verified ISO, separate 4-vCPU/8-GiB/60-GiB guest, host-only networking, scoped Windows firewall rule and capture group. Choose only the new VM's empty disk for installation.
2. On Windows run the following from the checkout in PowerShell. Python must be 3.12 or later. Put the runtime outside OneDrive; the example uses `%USERPROFILE%\HealthcareSOCLab\hospital`. That directory must not contain an existing hospital or VM. If occupied, choose a new private runtime and set that same path everywhere; do not remove an old runtime to make seeding pass.

   ```powershell
   .\scripts\setup-windows.ps1 -Python python
   Copy-Item config\lab.example.json config\lab.local.json
   # Edit runtime_root to the actual absolute runtime path; verify 10.77.0.1/10 addresses.
   .venv\Scripts\python.exe -m pytest -q
   .venv\Scripts\python.exe scripts\build-dashboard.py
   .venv\Scripts\python.exe scripts\check-clean-install.py
   ```

   Preserve `requirements-lock.txt`, the setup/test output and `build-check/<UUID>/result.json` privately. The clean-install script deliberately reproduces the missing-build-backend failure without isolation, then tests the fixed isolated editable install in a new venv. It uses `--no-deps`; this checks packaging only, not dependency availability or application/SIEM behavior. Use normal build isolation for actual installation, as the setup scripts do.
3. Install matching Wazuh 4.14.10 central components and Windows agent using the [official installation procedure](https://documentation.wazuh.com/current/installation-guide/index.html); retain installer/package checksums and credentials privately. Record the actual Filebeat/indexer versions rather than assuming their underlying versions from the Wazuh release. Pin or hold the selected packages for the measured session. Installation downloads may use temporary NAT; disconnect it before measured traffic.
4. Follow [archive and mapping setup](../siem/manager-archives.md) **before first hospital indexing**. Enable JSON archives and Filebeat archives forwarding; merge `data.bytes_sent: long`, `data.http_status: integer`, `data.duration_ms: long` into the complete local Wazuh template, load it into `_template/wazuh`, and save mapping/field-capability responses for both data views. If indices already have conflicting mappings, use the separately reviewed migration path there. Do not silently reindex/delete the preserved installation.
5. Install the checked-in rules; validate with `wazuh-analysisd -t` and restart the manager. Merge rendered localfile/FIM snippets into the existing Windows agent configuration using the exact runtime path. Keep unrelated settings. Start the agent and allow the initial FIM scan to finish. Record `hospital-win`'s active agent ID/version. Use [handoff preparation](operator-handoff.md) and `scripts/setup-linux.sh` to install the guest project/dependencies and copy only the needed private runtime secrets with restricted permissions.
6. Start the hospital server on Windows (`.venv\Scripts\python.exe -m hospital_soc --config config\lab.local.json serve`). From the guest verify `/health` at `http://10.77.0.1:8080/health`, the selected capture interface/permissions, all four services, source/manager clock offset, and actual archive forwarding. A populated local `archives.json` is insufficient without indexer visibility. Test one bounded dummy-file edit and old/new SHA-256 corroboration, then restore before measurement.
7. Run `sudo .venv/bin/python scripts/verify-native-rules.py --output NEW_PRIVATE_PROOF_DIR` in the guest checkout. Require schema 3, 26/26 cases including installed-revision challenge and all three acknowledged >60-second expiry controls. Preserve failed attempts. Use the [native validation procedure](2026-11-13-native-revalidation.md) for raw proof inspection and installed-rule hash/revision comparison; example historical hashes are valid only for that exact rule revision.
8. Complete the 15-minute stability observation, 30-minute calibration, three independent 10-minute holdouts, three measured repetitions per attack, enforce-mode repetitions and S3 approved/size controls. Use fresh run directories and the [run/evaluation contract](operator-handoff.md), including initial FIM inventories, receiver files, packet captures/drop counters, source/manager evidence, current native proof, contemporaneous clock/per-minute resource/first-index observations (`scripts/measure-run-timing.py`), timestamped 50-hash restoration receipts (`scripts/reset-lab.ps1` / `hospital_soc restore --receipt`), and >=65-second inter-run drain/quiet interval. Preserve every attempt, evaluate each completed run, and inspect the packet/query outputs manually.
9. Execute [Q1-Q6](../siem/queries.md) on the rebuilt indexer with actual opaque run IDs and exact UTC time bounds. Export JSON/CSV and reconcile source event IDs, FIM path/digest attribution and receiver bytes/digests. In Saved objects import `siem/dashboard.ndjson` with its references into the intended tenant. Refresh the archive/alert data-view fields and inspect all eight panels for errors and meaningful values. Confirm numeric export sums and the saved ten-second auto-refresh; select historical absolute times when examining an older run outside `now-4h`.
10. Test collection health visibly: a current source heartbeat yields `FRESH`; after >90 seconds without a new source heartbeat it yields `STALE`; an empty query and invalid/future source clock yield `UNKNOWN`. Preserve screenshots, browser errors if any, refresh-transition evidence and a new dashboard export. Test the separate native agent connection view as well. Stopping Filebeat tests forwarding interruption; it does not establish native Windows agent-disconnect latency. Record which service was stopped, its privileges and the observed recovery interval. The original manager used a 15-minute agent-disconnection timeout, and its non-admin Windows shell could not stop `WazuhSvc`.

## Evidence and acceptance checklist

Store a private record with operator, machine/VM identity, UTC start/end, checkout revision, installed versions, commands and outcomes. Never put credentials, raw capture authorization headers, runtime secrets or private environment inventories into Git. Hash finalized evidence and retain original paths and failed attempts.

| Gate | Evidence required on the new installation |
|---|---|
| Source and packages | Revision, clean-checkout status, OS/Python/package versions, dependency installation and test logs |
| Isolation and reachability | Addresses/routes, scoped firewall rule, all four services, active agent, captured cross-host smoke request |
| Collection and mappings | JSON archive configuration, template export, actual mappings/field caps, unique source-to-index reconciliation |
| Native behavior | Installed rule hash/revision, schema-3 26/26 proof/transcripts, native FIM old/new digest match |
| Measurement | Stability/calibration/holdouts/attack/control manifests, PCAPNG/CSV/drop evidence, receivers, observations, evaluator outputs |
| Analyst visibility | Q1-Q6 query/time metadata and exports, eight rendered panels, health transitions, saved-object re-export |
| Clean setup and packaging | Automated isolated packaging check (`scripts/check-clean-install.py`, exit `2` -> `0`) and verified 50/50 restoration receipts; separate teammate VM retesting waived |

The packaging check was rerun on November 14 in a fresh local venv: the non-isolated install returned 2, the isolated install returned 0, and `regression_reproduced` / `fixed_install_passed` were both true. Separate clean-VM retesting by another group member is **not required** (waived per project scope decision); this guide remains a reference procedure for any fresh installation.
