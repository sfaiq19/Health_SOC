# Operator handoff with Codex closed

The software can be developed with the VM off. This runbook is the first-setup and live-evidence handoff, not a statement that those gates passed. Exact installed Wazuh versions and the final network must be recorded here after setup.

If the installer transfer is interrupted, resume it from the project directory with `.venv\Scripts\python.exe -u scripts\download-ubuntu.py`. Run only one copy at a time. It resumes the stable user-profile `.part` file using checked ranges and publishes the ISO only after SHA-256 verification.

## First setup requiring operator interaction

1. Wait for the Ubuntu download to finish and for `ubuntu-verification.json` beside it to confirm the complete ISO checksum. The VM points to the final ISO, not `.part`. Open `%USERPROFILE%\HealthcareSOCLab\vm\Healthcare-SOC.vmx` in VMware only after freeing memory and closing Codex. The configuration is 4 CPUs, 8192 MiB and 60 GiB disk. The user-profile directory avoids packaged-AppData redirection.
2. Before first boot, configure a dedicated host-only network for `10.77.0.0/24`, host address `10.77.0.1`, and select it on the lab VM. Do not change networks used by existing VMs. Give the Ubuntu guest `10.77.0.10/24`. Confirm no bridged or NAT interface is active for measured traffic. Installation-time NAT may be enabled temporarily for package downloads and must then be disconnected.
3. Install Ubuntu Server 24.04 from the verified ISO. Create the dedicated `labuser` account, use a new disposable password, install OpenSSH if needed, and record the SSH host-key fingerprint. Keep unrelated disks/VMs disconnected. The new 60 GiB virtual disk is the only installation target.
4. Install Wazuh all-in-one according to its official quickstart, pin matching manager/indexer/dashboard/agent packages and record versions. Do not interpret the candidate XML or dashboard as installed. Preserve installer credentials privately. Verify dashboard authentication and indexer health; copy `siem/healthcare_rules.xml` to `/var/ossec/etc/rules/healthcare_rules.xml`, restart manager and check errors.
5. On Windows install the matching signed Wazuh agent package with manager `10.77.0.10` and agent name `hospital-win`; start `WazuhSvc`. This requires administrator access. Seed the hospital runtime using the setup command below before configuring its pre-existing dummy directory. Merge rendered `siem/agent-localfile.xml` and `siem/agent-fim.xml` snippets into the existing agent configuration, replacing `__RUNTIME_ROOT__` with the hospital runtime. Preserve unrelated settings, restart the agent, and wait for the FIM baseline scan. Configure archive forwarding using `siem/manager-archives.md`.
6. Install Wireshark/dumpcap on the VM and configure the capture group. Configure a narrowly scoped Windows inbound firewall rule: local `10.77.0.1:8080/TCP`, remote `10.77.0.10`. Verify actual binding and a captured smoke request before long runs. Do not disable the Windows firewall. Record clock offset and 15-minute stability.

Windows project setup, once:

```powershell
.\scripts\setup-windows.ps1 -Python "$env:USERPROFILE\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
Copy-Item config\lab.example.json config\lab.local.json
# Replace YOUR_USERNAME in runtime_root with a private Windows user path outside OneDrive.
.venv\Scripts\python.exe scripts\prepare-handoff.py --runtime "$env:USERPROFILE\HealthcareSOCLab\hospital"
.\scripts\copy-handoff.ps1
```

The private archive contains disposable lab credentials and must only go to the isolated guest. `scp` will ask for the guest password and may ask you to verify the previously recorded SSH host-key fingerprint. It must not be uploaded or committed. In Ubuntu:

```bash
sudo apt-get install -y unzip
unzip healthcare-soc-handoff.zip -d healthcare-soc-handoff
mkdir -p /home/labuser/healthcare-soc-runtime
cp healthcare-soc-handoff/runtime/secrets.json /home/labuser/healthcare-soc-runtime/secrets.json
chmod 600 /home/labuser/healthcare-soc-runtime/secrets.json
mv healthcare-soc-handoff/project /home/labuser/healthcare-soc
cd /home/labuser/healthcare-soc
bash scripts/setup-linux.sh
```

If setup fails, preserve its error output and return it to Codex; do not mark a gate complete. No BIOS change is inferred from the Windows firmware flag alone.

## Routine run

On Windows, leave the small hospital process running, then close Codex:

```powershell
.venv\Scripts\python.exe -m hospital_soc --config config\lab.local.json serve
```

On Ubuntu identify the host-only interface with `ip -4 addr` and `dumpcap -D`, then run the native rule tests once per rule revision:

```bash
sudo .venv/bin/python scripts/verify-native-rules.py --output /home/labuser/native-rule-proof
```

All cases must pass; retain raw logtest output. This command includes a real 61-second window-expiry test. If it fails, return the results for repair before measured trials. It never uses a local Python rule emulator.

To run a single scenario, replace `ens33` with the verified interface and choose a new run directory:

```bash
bash scripts/run-lab-scenario.sh s1 ens33 /home/labuser/evidence/run-001
```

This starts two local receivers and packet capture, runs the scenario with real timing, waits 30 seconds, stops only its own processes, and exports packet fields. Generator output stages under `RUN/generated` because the top-level capture directory already contains files; the script then copies the manifest and hashes into the evidence root. **Do not point a generator directly at a directory already populated by capture.sh.** Existing evidence is never overwritten.

Before S2 stop benign document edits and reset the dummy files with the Windows service stopped, then restart it, wait for FIM stabilization and record hashes. Other benign modules can run separately. After each run reconcile previous source events with Wazuh ingestion before the 65-second quiet interval. The script does not claim to have verified this drain; it requires collection evidence.

For 30-minute calibration and separate 10-minute holdouts, run both receivers in separate terminals and use `baseline --minutes 30 --output NEW_DIRECTORY` (or `--minutes 10`). Use the same capture staging layout. The default baseline includes approved exports. `--without-exports` and `--diagnostic` are development options and do not fulfill the full baseline gate.

## Evidence to collect before evaluation

Copy the run's source audit events from the Windows `hospital/logs/app.jsonl`; export corresponding Wazuh archives and alerts without renaming source events as Wazuh output. Preserve native FIM alerts, the actual installed rules file and native proof. For S3 also copy the VM receiver JSONL and received `.bin` object into `RUN/received`. Export the six real SIEM searches and time bounds and save readable screenshots.

Create `observations.json` from measured values, not target values: `max_clock_offset_ms`, `max_index_visibility_delay_s`, `capture_dropped_packets`, and UTC `collection_checked_at`. It must be at or after the run end and all current-run manager timestamps, within 120 seconds of the end. Actual archive timestamps must agree with source times and collection deadlines; a manually entered delay of zero cannot override late archives.

For the first measured run set `first_measured_run` to true only if there is no preceding measured run. For later runs set it false and record `previous_measured_run_id`, `prior_run_final_manager_at`, and `quiet_interval_started_at`. Start only after at least 65 seconds of quiet following the recorded drain. If a later event for that previous run is observed, the drain evidence is invalid and the overlapping run must be repeated. Preserve prior-run events in the collection window where relevant.

Save the commands/raw observations that support those values. Do not assume zero drops because none were noticed. Put `native-rule-tests.json` and the matching `healthcare_rules.xml` into each finalized run. Packet export now includes request headers for run-ID binding; the evaluator requires a structurally valid, nonempty PCAPNG and uses installed tshark to re-export the file and compare the CSV exactly. Unrelated or independently edited CSVs cannot pass. The capture contains disposable lab credentials: retain privately and retire those credentials after evaluation.

```bash
.venv/bin/python -m hospital_soc evaluate --run-dir /home/labuser/evidence/run-001
```

Exit zero means the implemented evidence checks found no listed gap; manually inspect packet details and query/dashboard outputs as well. Diagnostic, missing-channel and failed-generator runs must remain incomplete/invalid. S2's automated evaluator requires native digest matches; if the installed engine omits them, retain the evidence for explicit manual path/time attribution review rather than weakening the gate.

Import `siem/dashboard.ndjson` into Dashboard management Saved objects, verify numeric/keyword fields, inspect all eight panels and export it again from the live system. Its Vega health panel computes source-heartbeat freshness on a one-second timer: older than 90 seconds is stale; empty, malformed or future clock values are unknown. Set dashboard query refresh to ten seconds and test loss/recovery with the agent stopped/restarted. Check native agent connection status separately. The Vega definition is prepared but native import/rendering remains unverified. Report and second-student rebuild gates remain pending until completed.

After the run stop the VM, reopen Codex, and provide the finalized evidence directories. Codex can inspect the saved files and repair the software without sharing RAM with Wazuh.
