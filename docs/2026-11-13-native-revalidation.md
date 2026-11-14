# November 13 lab continuation

Start here on the installed VM. The [diagnostic audit](2026-11-13-diagnostic-audit.md) records the evidence and [acceptance ledger](implementation-progress.md) tracks the remaining work. Original private bundles and the failed proof must retain their original names and bytes.

## Repository assessment and offline work order

Starting checkout was clean on main at 5b90d33. Flask and SQLite own clinical state, clients produce request receipts, Wazuh archives/alerts and native syscheck provide independent collection evidence, and the evaluator joins those channels with packet fields. The prepared dashboard and formal evaluation sessions still need execution.

1. Verify the private archive SHA-256, inventory, source/archive joins, FIM hashes, receiver/capture integrity and full native result arrays. Preserve credential-bearing artifacts outside Git.
2. Restore the four native action selectors and revision from the tested Ubuntu XML in siem/healthcare_rules.xml. Add a classifier regression in tests/test_siem_contracts.py.
3. Add acknowledged engine timing and raw-reply validation in scripts/verify-native-rules.py and src/hospital_soc/native_validation.py. Version the evidence schema and test missing acknowledgement, stale clocks, session replacement and complete event sequences.
4. Integrate schema-3 replay checks, Windows FIM path matching, eligible alert actions, malformed-ID rejection and order-response chronology in evaluate.py and evidence_contract.py. Add adversarial tests through the evaluator and CLI.
5. Run the complete offline tests and fresh loopback workflows. Keep actual outcomes and restoration results in the ledger.
6. Run the bounded operator session below before calibration, holdouts, nine measured attacks, dashboards and the report.

## Why the three expiry controls need another native run

On Wazuh 4.14.10 all 4/19/19 prefix events classified as expected. Only the final event of each case produced 110101/110103/110201 instead of 110001/110002/110003. The installed revision challenge passed. The separate live auth experiment stayed below five failures per rolling minute and produced zero 110101 alerts. Neither read nor write expiry was observed in that experiment.

The tagged [CLI](https://github.com/wazuh/wazuh/blob/v4.14.10/framework/scripts/wazuh_logtest.py) reads a line and synchronously requests analysis using a session token. It warns if the server replaces the session. The [logtest daemon](https://github.com/wazuh/wazuh/blob/v4.14.10/src/analysisd/logtest.c) cleans each submitted message and matches against session history. [Message processing](https://github.com/wazuh/wazuh/blob/v4.14.10/src/analysisd/cleanevent.c) sets event generation time from the manager clock. [Search_LastGroups](https://github.com/wazuh/wazuh/blob/v4.14.10/src/analysisd/eventinfo.c) expires history when the current time minus the earlier event generation time is **greater than** the rule timeframe. Its production path reads a [shared analysisd time value](https://github.com/wazuh/wazuh/blob/v4.14.10/src/analysisd/analysisd.c).

The previous driver started its 61-second sleep after writing the prefix into a pipe. The last prefix event could still be queued or processing while the sleep ran. A delayed shared clock update could also reduce the effective interval. The old transcripts give classifications but no per-event engine clock measurements or timing acknowledgement. They do not establish which explanation caused the historical failure. A fresh session for the final event would discard history and make the control meaningless.

The revised driver uses schema 3. It requests debug replies for expiry cases, acknowledges every submitted event before advancing, then waits 65 seconds after the last prefix acknowledgement. The proof requires unique source identities, one stable session within each expiry case, independent sessions between cases, a prefix completed within 60 seconds, and an engine-timestamp gap greater than 60 seconds. All 26 raw transcripts are hashed and reparsed by the evaluator. Old schema-2 proof stays historical and requires fresh revalidation. Thresholds and expected rule sequences retain their original values. The longer wait and new proof format are engineering choices to measure the existing expiry requirement.

## One bounded operator session

**Windows, ordinary PowerShell.** After booting the existing VM, check the lab link, scoped firewall rule, agent and source server. Start Flask in a separate project terminal if port 8080 is idle. Keep port 8080 bound to the host-only address. Use the existing VMnet4 and verified SSH fingerprint.

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Desktop\SOC Project"
Get-Service WazuhSvc
Get-NetFirewallRule -DisplayName 'HealthcareSOC-Hospital-8080-VMnet4' | Get-NetFirewallAddressFilter
Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
Test-NetConnection 10.77.0.10 -Port 22
# Only if Flask is stopped, in the separate terminal:
.venv\Scripts\python.exe -m hospital_soc --config config\lab.local.json serve
```

From the Windows project directory use a new private staging directory on the guest. The transfer contains repository Python sources and the candidate XML. This also updates the evaluator used in subsequent guest runs. If a transfer fails, resolve it before installing anything.

```powershell
$tag = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$guest = 'labuser@10.77.0.10'
$stage = "/home/labuser/revalidate-$tag"
ssh $guest "umask 077 && mkdir '$stage' && mkdir '$stage/src'"
if ($LASTEXITCODE) { throw 'Staging failed' }
scp siem/healthcare_rules.xml scripts/verify-native-rules.py "${guest}:$stage/"
if ($LASTEXITCODE) { throw 'Driver or XML transfer failed' }
Get-ChildItem src/hospital_soc/*.py | ForEach-Object {
    scp $_.FullName "${guest}:$stage/src/"
    if ($LASTEXITCODE) { throw "Transfer failed for $($_.Name)" }
}
Write-Output $stage
```

**Ubuntu, logged in as labuser.** In a new Bash terminal paste the printed stage path at the prompt. Run the following as one block in a shell with `set -e` so a failed precondition stops installation. Backups stay outside loaded rule directories.

```bash
set -eu
umask 077
read -rp 'Absolute path printed by Windows: ' STAGE
test -d "$STAGE/src" && test -s "$STAGE/verify-native-rules.py"
cd ~/healthcare-soc
ip -br addr
ip route get 10.77.0.1
test -z "$(ip -4 route show default)"
test -z "$(ip -6 route show default)"
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo /var/ossec/bin/agent_control -lc
curl -fsS --max-time 5 http://10.77.0.1:8080/health
dumpcap -D
tag=$(date -u +%Y%m%dT%H%M%SZ)
backup="$HOME/pre-revalidation-$tag"
mkdir -m 700 "$backup"
tar -czf "$backup/project-before.tar.gz" scripts/verify-native-rules.py src/hospital_soc siem/healthcare_rules.xml
sudo cp -p /var/ossec/etc/rules/healthcare_rules.xml "$backup/installed-before.xml"
sha256sum "$STAGE/healthcare_rules.xml"
echo "8a71944c501ec8a0b15ccb7c910c96e762f71976ad0be1da49512397fb5eb4bb  $STAGE/healthcare_rules.xml" | sha256sum -c -
cp "$STAGE"/src/*.py src/hospital_soc/
cp "$STAGE/verify-native-rules.py" scripts/
cp "$STAGE/healthcare_rules.xml" siem/
.venv/bin/python -c 'import hospital_soc.native_validation as n; print(n.__file__); print(n.rule_revision(open("siem/healthcare_rules.xml").read()))'
sudo install -o root -g wazuh -m 0640 siem/healthcare_rules.xml /var/ossec/etc/rules/healthcare_rules.xml
sudo cmp siem/healthcare_rules.xml /var/ossec/etc/rules/healthcare_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
systemctl is-active wazuh-manager
sudo /var/ossec/bin/agent_control -lc
```

Confirm the interface is ens192, the address is 10.77.0.10, the Python module comes from the guest checkout, the revision starts with `db7629b4` and **001 hospital-win is active again**. If config testing fails, save stderr. To restore the exact previous candidate use `sudo cp -p "$backup/installed-before.xml" /var/ossec/etc/rules/healthcare_rules.xml`, validate with `wazuh-analysisd -t` and restart only after validation succeeds.

**Run the whole native suite in the same terminal.** Allow several minutes; the expiry controls require real waits. Restrict access to the debug proof as it can contain session tokens.

```bash
proof="$HOME/native-rule-proof-$(date -u +%Y%m%dT%H%M%SZ)"
test ! -e "$proof"
rc=0
sudo .venv/bin/python scripts/verify-native-rules.py --output "$proof" || rc=$?
printf 'driver exit=%s proof=%s\n' "$rc" "$proof"
sudo .venv/bin/python - "$proof/native-rule-tests.json" <<'PY'
import json, sys
from pathlib import Path
p = json.loads(Path(sys.argv[1]).read_text())
print("engine", p["version"].splitlines()[0], "schema", p["validation_schema"])
print("passed", sum(c["passed"] is True for c in p["cases"]), "/", len(p["cases"]))
print("failed cases", [c["case"] for c in p["cases"] if not c["passed"]])
assert len(p["cases"]) == 26 and p["success"] is True and all(c["passed"] for c in p["cases"])
PY
test "$rc" -eq 0
```

Keep the proof directory, including raw transcripts, exact XML, engine version and snapshots even on failure. A successful validation requires all 26 named cases, correct full event sequences, the installed revision challenge and the new timing evidence. A missing JSON file or timeout is a failed attempt. After success, copy the proof JSON, exact XML and required transcript files into each fresh measured bundle (retain the entire private proof as provenance). Export and evaluate captures on the same Ubuntu tshark build. For S3 copy the original received object to `RUN/received/<transfer_id>.bin` privately before evaluation.

### If an expiry case still fails

Preserve raw per-event debug output privately. Check engine times, same-session continuity, actor and unique event identities, prefix duration, final gap, manager load and the actual Phase 3 IDs. A changed session or compressed manager timestamps make that attempt unusable. If session and timing are correct and the burst still fires, record a native discrepancy. Preserve the failed proof.

Independent follow-up design for live-manager testing: for each family use a fresh opaque run ID and actor, plus another isolated actor as a near-threshold interference control. Deliver uniquely identified synthetic audit events through the actual monitored app JSONL on hospital-win in a diagnostic maintenance window. Send N−1 matching events (N = 5, 20, 20), confirm all N−1 in the manager archives, wait at least 65 seconds after the last confirmed arrival, then send one matching event. For each negative stream require every input ID exactly once after deduplication, recorded duplicates, matching actor/action, source and manager timestamps supporting a gap >60 seconds, and no matching burst for that actor after final collection. Run a separate positive control of N matching events within 60 seconds for each family and require its correct burst. Verify each other actor stays below threshold during interleaved controls. Retain source, archives, complete alert window, IDs, receipt times, clock measurements, native revision and final drain. Treat overlapping measured windows or incomplete collection as inconclusive. This experiment diagnoses the live engine; it cannot convert a failed 26-case proof into success.
