# Healthcare SOC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking. This document authorizes planning only; product implementation is a subsequent task.

**Goal:** Deliver a reproducible Healthcare SOC lab that detects and explains three controlled attacks using hospital application events, native file-integrity evidence, Wireshark, and Wazuh.

**Architecture:** Windows hosts the synthetic hospital service and Wazuh endpoint agent. One isolated Ubuntu VM hosts Wazuh central components, normal/attack clients, and two local export receivers. Actual HTTP activity crosses the host-only interface for packet capture; raw events, alerts, and ground truth remain distinguishable.

**Tech stack:** Wazuh 4.14 documentation family, Ubuntu Server 24.04 LTS, Windows host, Python 3.12, Flask 3.1 API family, SQLite, pytest, Wireshark/dumpcap, and one hypervisor. Pin tested patch versions during setup. No frontend framework, full EHR, ML platform, or paid cloud service is required.

**Spec:** [Healthcare SOC design](../specs/2026-10-22-healthcare-soc-design.md). **Assignment:** [Project.docx](../../../Project.docx). **Planning date:** 22 October 2026. **State:** implementation authorized; Task 1 environment checks started. Live acceptance remains pending. [Execution ledger](../../implementation-progress.md) records actual results; unchecked steps below are unverified.

## Global constraints

- Three students; three controlled scenarios; grading weights 30 simulation, 30 attacks, 40 detection.
- Use only synthetic records, simulated identities/devices, and the isolated lab network.
- Windows `10.77.0.1`, VM `10.77.0.10`, subnet `10.77.0.0/24`, subject to collision check.
- One VM: 4 vCPU, 8 GiB RAM, 60 GB disk; validate stable operation before adding features.
- Runtime data on Windows: `$env:USERPROFILE\HealthcareSOCLab\hospital`; on Linux: `/home/labuser/healthcare-soc-runtime`. Neither directory is a source checkout or a synchronized evidence folder. The Windows path was revised after packaged-AppData redirection was verified; see the execution ledger.
- App port 8080; unapproved lab receiver 9080; approved lab receiver 9081; Wazuh dashboard 443; agent events 1514; enrollment 1515 restricted to setup; SSH 22 for administration. Do not expose internal indexer/API services externally.
- Real requests and file changes generate evidence. No fabricated screenshots, pre-filled success metrics, or hard-coded detection based on scenario labels.
- All timestamps are UTC ISO 8601 with milliseconds. A source event time and a Wazuh processing time are different measurements. Record both.
- Default mode `observe` models two permissive policies; `enforce` demonstrates remediation. Authentication, role checks, path limits, and lab destination limits always apply.
- No automatic endpoint isolation or account deletion. Response is an analyst playbook and controlled policy rerun.
- Source and deliverable paths below are relative to the project root unless explicitly absolute. No implementation files listed below have been created by writing this plan.

## Review focus

1. Missing/delayed telemetry must produce an incomplete run and stale dashboard state; test in Tasks 4 and 8.
2. Threshold edges, different users, repeated records, and separate runs must not accidentally share frequency state; test in Tasks 5 and 8.
3. File mutation and reset must reject path traversal, links, and paths outside the dedicated dummy directory; test in Tasks 2 and 6.
4. Sender success must not imply receiver success; verify actual bytes and digest, and failed delivery behavior in Task 7.
5. Ground truth, labels, and run names must not become detection shortcuts; test renamed runs and audit rule inputs in Tasks 5 and 8.

## Deliverables and marks

| Rubric area | Marks | Concrete delivery | Evidence gate |
|---|---:|---|---|
| Simulation and architecture | 30 | Architecture/protocol diagram, EMR, LIS, device monitoring, auth, reproducible environment | Real requests change/read state; baseline contains all four domains |
| Attack generation | 30 | S1, S2, S3 procedures, bounded runners, normal comparison, ground-truth manifests | Requests/file hashes/receiver output establish what actually occurred |
| Wireshark and SIEM detection | 40 | Packet analysis, Wazuh rules, executed searches, alerts, dashboard, evaluation | Saved raw captures and query exports trace every reported conclusion |

Technical report, screenshots, mitigation recommendations, source/configuration, and group contributions accompany these artifacts. The assignment does not prescribe the panel count, test thresholds, or four-week duration; those are design choices in this plan.

## Architecture and protocol decisions

Read the design's diagram first. Use a host-only virtual switch, never a bridged hospital lab. Installation may temporarily use NAT; measured runs disable it. Windows firewall admits the VM to the hospital port only. VM receivers bind to its host-only IP and accept the Windows host only. Wazuh receives the agent and exposes its dashboard to the host.

| Layer | Implemented protocol | Demonstrated role |
|---|---|---|
| Link/network | Virtual Ethernet, IPv4, ARP | Address resolution and host-to-VM communication |
| Transport | TCP | Sessions, connection establishment, byte/packet patterns |
| Hospital application | HTTP/1.1 with JSON on 8080 | Authentication, records, labs, device updates, document operations |
| Export | HTTP POST on 9080/9081 | Measured synthetic data transfer to two policy-distinct destinations |
| SOC | Wazuh agent transport; HTTPS dashboard | Endpoint collection and analyst access |
| Persistence | SQLite and local files | Synthetic record state, audit JSONL, monitored dummy documents |

Explain where HL7/FHIR, DICOM, identity infrastructure, and medical-device gateways would fit in a larger system. Do not label the custom JSON API as standards compliant. The VM and Windows host are two physical execution environments; the hospital's modules are logical simulations, and the one subnet does not demonstrate network segmentation.

## Hospital workflows and interface contract

Seed 200 patients across `ward-a`, `ward-b`, and `ward-c`; six named synthetic human accounts; one laboratory service account; ten device identities; a care-assignment table; and 50 dummy document files. Use a fixed generator seed and a source-controlled seed specification. Passwords and bearer tokens remain runtime secrets and are excluded from audit events and source control.

Implement `create_app(config: LabConfig) -> Flask` and test routes with Flask's test client before live network tests. Database operations must be parameterized and transactional. Bind the lab service to the host-only address, with the development debugger and reloader disabled. A small foreground Flask server is sufficient for the bounded lab; document that it is not a production deployment.

| Route | Actor and result | Authoritative event action |
|---|---|---|
| `POST /api/auth/login` | Valid credentials issue a temporary session; invalid credentials return 401 | `login_success` or `login_failure` |
| `GET /api/records/<patient_id>` | Authenticated clinician/nurse reads fictional record; apply care policy by mode | `record_read` or `record_denied` |
| `POST /api/lab/orders` | Clinician creates a lab order | `lab_order_created` |
| `POST /api/lab/results` | Lab role posts a result for an existing order | `lab_result_created` |
| `POST /api/devices/<device_id>/telemetry` | Matching device credential posts a synthetic reading and heartbeat | `device_telemetry` |
| `PUT /api/documents/<document_id>` | Permitted lab user updates an existing manifest-listed dummy file | `document_update` |
| `POST /api/exports` | Records clerk selects one registered destination ID and bounded export size | `export_completed`, `export_failed`, or `export_denied` |
| `GET /health` | Status of app, database, log writer, and runtime identity; no secrets | `service_heartbeat` every 30 seconds via the workload |

Do not build an `/attack` endpoint. The scenario runner uses the same routes as normal clients. The document route accepts an opaque known ID, never a raw path. The export route accepts `approved-lab` or `unapproved-lab`, never a caller-supplied URL. Reject payloads above 10,000,000 bytes, redirects, and destinations outside the configured lab mapping in both policy modes.

Clients send opaque UUIDs in `X-Lab-Run-ID` and `X-Request-ID`; the server validates them and echoes `X-Request-ID` in responses. Controlled runs reject malformed IDs. The server obtains identity from the session, never these correlation headers. For failed logins, log the normalized attempted synthetic account ID with `actor_role=unauthenticated`, allowing the failed-attempt series to share an actor key without claiming the caller was authenticated.

Human role model: clinician and nurse can read records; clinician creates lab orders; laboratory role posts results; records clerk exports; a document-editor lab role updates dummy documents; administrator manages seed/configuration through local tooling. Device credentials cannot call human routes. Use six human accounts covering those roles; add multiple clinical accounts only if needed by the cross-actor tests.

### Audit schema

Each completed request emits one UTF-8 JSON object followed by a newline. Keep events under 8 KB; omit patient content and credentials. Write/flush the event before returning the final response where feasible; if audit writing fails, reject the request before mutation or record the transaction failure explicitly. Do not report silent success with missing audit evidence.

| Field | Type and rule |
|---|---|
| `schema_version`, `service` | Integer `1`; constant `hospital-lab` |
| `event_id`, `event_time` | Unique UUID; UTC ISO timestamp assigned by the server |
| `run_id`, `request_id` | Validated correlation identifiers; never a detection condition |
| `action`, `outcome` | Controlled action vocabulary; `success`, `failure`, or `denied` |
| `actor_id`, `actor_role`, `source_ip` | Successful authenticated requests: verified session/credential identity and socket IP. Failed login: normalized attempted account ID, role `unauthenticated`, socket IP; this is not proof of that user's identity. Never trust a claimed role or forwarded-IP header |
| `actor_key` | Server-generated `actor_id|source_ip`, for frequency correlation |
| `patient_id`, `care_scope` | Record actions only; `assigned` or `unassigned` from the server's care table |
| `document_id`, `path`, `sha256_before`, `sha256_after` | Document actions only; canonical path and measured hashes |
| `destination_id`, `destination_approved`, `destination_ip`, `destination_port` | Export actions only; approval string `yes`/`no` derived from configuration |
| `bytes_sent`, `payload_sha256`, `transfer_id` | Completed exports only; actual request-body byte count, digest, unique transfer ID |
| `http_status`, `duration_ms` | Numeric response status and request duration |

Raw app field `action` will normally be indexed as `data.action`, with other dynamic fields similarly under `data`. Verify the actual mapping before saving searches. Native FIM uses `syscheck.*`; do not pretend it carries application `run_id` or `request_id`. Join it through agent identity, known file paths, hashes where available, and the measured time interval.

Ground truth is separate: `run_id`, scenario, seed, policy mode, start/end UTC, intended operations, actual operation receipts, expected record/file sets, and success/failure of the generator. Never store `is_attack`, scenario names, expected rule IDs, or ground-truth labels in the monitored app JSONL. Attack and baseline run IDs use the same opaque format.

## Repository and evidence layout

```text
README.md                         entrypoint and reproducibility instructions
pyproject.toml                    dependency declarations and test configuration
requirements-lock.txt             tested exact dependency versions
config/lab.example.json           addresses, paths, identities, policy settings
src/hospital_soc/config.py        typed configuration and startup validation
src/hospital_soc/contracts.py     LabConfig, AuditEvent, RunManifest contracts
src/hospital_soc/app.py           factory and route registration
src/hospital_soc/store.py         SQLite schema, seed, transactions
src/hospital_soc/auth.py          sessions and role checks
src/hospital_soc/clinical.py      EMR, LIS, and device routes
src/hospital_soc/documents.py     bounded real file updates
src/hospital_soc/exports.py       bounded transfers and sender receipts
src/hospital_soc/audit.py         structured event validation and writes
src/hospital_soc/receiver.py      bounded receivers and independent receipts
src/hospital_soc/workload.py      normal client workload
src/hospital_soc/scenarios.py     S1, S2, S3 client sequences
src/hospital_soc/evaluate.py      evidence joins, completeness, metrics
src/hospital_soc/__main__.py      CLI dispatch
tests/                            unit, route, boundary, and contract tests
tests/fixtures/                   small sanitized event sequences for logtest
scripts/setup-windows.ps1          Windows runtime and service instructions
scripts/setup-linux.sh            VM dependencies and setup checks
scripts/capture.sh                interface validation and bounded dumpcap
scripts/reset-lab.ps1             checked dummy-data restore
siem/agent-localfile.xml          app log input snippet
siem/agent-fim.xml                monitored dummy directory snippet
siem/manager-archives.md          archive and Filebeat settings
siem/healthcare_rules.xml         custom rules only
siem/queries.md                   executed Discover queries and aggregations
siem/dashboard.ndjson             exported saved dashboard objects
docs/environment.md              exact packages, network, resources, setup
docs/protocols.md                 implemented stack and healthcare limits
docs/playbooks.md                 triage, response, recovery
docs/demo.md                      timed demonstration
evidence/<run_id>/                copied, finalized evidence for one run
report/Healthcare_SOC_Report.docx final report, authored after real results
```

Each finalized run directory contains `manifest.json`, `app.jsonl`, `alerts.jsonl`, relevant `archives.jsonl`, `traffic.pcapng`, `capture-stats.txt`, `receiver.jsonl` when applicable, `file-hashes-before.json` and `file-hashes-after.json` when applicable, `query-results/`, `screenshots/`, `metrics.json`, and `checksums.sha256`. Explain any non-applicable file in the manifest. Keep secrets, installer credentials, active databases, and ground truth out of watched paths. Export through authenticated access; retain the complete final evidence bundle separately from shorter live-index retention.

## Detection specification

Use custom IDs 110000–110399, within Wazuh's recommended custom range. Create rules in `healthcare_rules.xml`; do not edit shipped rules. Base event classifiers used by frequency rules must remain at level 1 or above because level-0 events cannot support the documented historical matching behavior. Validate using `wazuh-logtest`, then restart the manager and repeat through live ingestion. [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html) and [rule syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html) are the implementation references.

| Rule | Condition and scope | Level | Required boundary checks |
|---|---|---:|---|
| 110101 | At least 5 `login_failure` events for the same `actor_key` in 60 s | 10 | 4/5/6 failures; 61 s separation; two actor keys |
| 110102 | Successful `record_read` with `care_scope=unassigned` | 8 | Assigned read and denied read must not match |
| 110103 | At least 20 successful `record_read` events for the same `actor_key` in 60 s | 10 | 19/20/21 events; actor separation; window expiry |
| 110201 | At least 20 successful `document_update` events for the same actor in 60 s | 12 | 19/20/21; failed writes excluded; low-rate edits |
| Native FIM | Changes under the exact dummy document root | Native level | Each S2 changed file corroborated; mapping exported from installed rules |
| 110301 | Successful export with `destination_approved=no` | 8 | Approved large export and failed transfer do not match |
| 110302 | Successful unapproved export with `bytes_sent >= 1000000` | 12 | 999999 / 1000000 / 1000001; approved destination |

Create level-1 classifiers 110001 for failed login, 110002 for successful record read, 110003 for successful document update, and 110004 for successful export. Put base grouping under 110000. Choose parent/child ordering so off-assignment reads still contribute to the read-frequency history. Test a stream containing both conditions: a single-event rule taking priority must not silently disable the frequency rule. The higher-severity export rule may supersede 110301 on the same event; acceptance expects the highest applicable rule, not duplicate alerts.

Assign inherited groups `hc_auth_failure`, `hc_record_read`, `hc_document_update`, and `hc_export_success` to those classifiers. Use `if_matched_group` with the corresponding group for history-based rules and `same_field` on `actor_key`; preserve the group in child matches. This avoids depending only on a base rule ID when a more specific child wins. Verify group inheritance and threshold behavior in the installed engine before accepting the implementation.

These thresholds are initial lab design values, not empirically proven hospital norms. Record-read frequency counts requests, not distinct patients; show unique-patient aggregation separately. S1 deliberately accesses 30 distinct records so the report can substantiate breadth without misdescribing the frequency rule.

For the numeric export threshold, constrain the schema to non-negative integer bytes and use a tested PCRE2 decimal range such as `^[1-9][0-9]{6,}$` for the selected 1,000,000-byte boundary. Do not compare string values lexicographically. If the pinned engine/schema needs another representation, change the implementation with the same boundary tests; do not change the agreed behavior silently.

Avoid global `ignore` settings that can hide another actor's incident. Retain raw alert events and deduplicate incident counts in evaluation by run, rule family, and actor/transfer. Reconcile the previous run's source events with ingested events first, then let at least 65 seconds elapse after its final manager-processed event to clear the longest frequency window. Record the final manager timestamp and quiet interval. A pause measured only from the generator stopping is insufficient when delivery is delayed. If a backlog remains or late prior-run events arrive, postpone the next run and restart the quiet interval; mark an overlapping attempted run incomplete. Rule fixture tests use a fresh logtest session per independent case.

Enable `logall_json` and Filebeat archive forwarding; create both archive and alert data views. Archive storage requires a small retention policy, proposed seven days, plus explicit disk usage monitoring. Normal events must be available even when they do not produce alerts. [Wazuh event archiving](https://documentation.wazuh.com/current/user-manual/manager/event-logging.html) describes the two configuration steps.

## Attack procedures and comparison traffic

### S1 Account misuse and suspicious record access

Baseline: an assigned clinician signs in, reads 3–8 assigned records per five minutes, and occasionally mistypes a password once. Scenario: issue six invalid login attempts over 30 seconds, then sign in with the known synthetic clinician account credential; read 30 distinct unassigned records over the next 45 seconds. API roles remain valid; care-assignment policy is in observe mode.

Expected: 401 responses for failures; 200 responses for permitted observe-mode reads; failed-login alert 110101, unassigned-read evidence 110102, and rate evidence 110103. Investigate sequence timing to associate success and reads with the failed attempts; no separate automatic failed-then-success correlation is claimed. Record actual rule precedence in exports.

Negative controls: one typo; four failures; repeated assigned reads below threshold; a busy authorized clinician; attempts using two different actor keys. Mitigation rerun: enable care-assignment enforcement, repeat the off-assignment requests, and show 403 responses with no record content returned. Discuss MFA and account-risk investigation as recommendations; MFA is not implemented in the core prototype.

### S2 Ransomware-like document activity

Baseline: a document editor updates at most two dummy documents per minute. Before the attack, seed all 50 files, save hashes, complete the native FIM baseline scan, and verify one harmless test update appears. Re-seed and stabilize before the measured run. Pause benign document edits from this preparation through post-run hashing and FIM collection; other baseline workflows continue. Record that exception in the manifest, and verify no unrelated write to the 50 target files occurred.

Scenario: submit one bounded update per second to each of the 50 known document IDs. Replace their dummy content with a harmless same-size marker payload; do not rename or encrypt files in the core scenario. Hash every file afterwards. Expected: 50 successful updates, 50 changed files, corresponding native FIM modification evidence, and document burst alert 110201. Enable SHA-256 checking and match native old/new digests to the before/after values where the installed event format exposes them. Record any missing digest fields explicitly; path/time attribution is acceptable only with verified exclusive writes and independent hashes. A burst alert alone does not pass this scenario.

Packet evidence shows rapid document PUT requests and responses. It cannot independently prove ransomware or filesystem damage; native FIM and hash differences establish actual changes. Restore from the seed backup; verify all original hashes. Stop traffic and record restoration as maintenance outside evaluation windows. Discuss least privilege, protected backups, and incident containment. No medical system is automatically isolated.

### S3 Unusual synthetic data export

Baseline: an authorized records clerk exports a 250,000-byte synthetic bundle to `approved-lab` on 9081. Include a benign 5,000,000-byte approved export as a size-only negative control. The bundle contains fictional records/attachments and is padded with explicitly synthetic content to reach the controlled byte count; it is not a claim about realistic record sizes.

Scenario: the same authorized role exports exactly 5,000,000 body bytes to `unapproved-lab` on 9080. Both targets are safety-approved local test services; only 9081 is approved by the fictional hospital's business policy. The Windows sender logs completion only after the receiver returns its independently measured size and digest and these match the sender's values. Capture the transaction; preserve the receiver's own log and received object.

Expected: rule 110302; the sender and receiver agree on payload SHA-256 and size; packet analysis identifies the destination, timing, and transfer. Wire bytes include headers/retransmissions and must not be presented as identical to application-body bytes. Negative controls: approved large transfer, unapproved small transfer producing 110301 only, receiver failure, digest mismatch, and oversize rejection. Mitigation rerun: enforce destination policy, show denial and no new received object.

## Wireshark analysis plan

Capture each baseline and attack run separately. Use `dumpcap -D` to identify the host-only interface; save its name/address in the environment record. Start capture before traffic, issue a known smoke request, then begin the run. Stop after a 30-second post-run collection period. Save capture drop statistics and the UTC interval. A missing handshake/request or unexplained packet loss requires repeating the run.

Proposed capture command on the VM, replacing `LAB_IFACE` with the verified interface:

```bash
dumpcap -i LAB_IFACE -f "host 10.77.0.1 and (tcp port 8080 or tcp port 9080 or tcp port 9081)" -w traffic.pcapng
```

This capture intentionally excludes Wazuh's encrypted log transport and dashboard traffic. If documenting those protocols, make a separate capture. Use the [dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html) for flags and [Wireshark display filters](https://www.wireshark.org/docs/man-pages/wireshark-filter.html) for analysis syntax. Configure Decode As HTTP for the custom ports when necessary.

| Evidence | Starting display filter | Analysis to save |
|---|---|---|
| S1 authentication | `http.request.uri contains "/api/auth/login"` | Failed-login sequence, corresponding response frames, actor from synthetic request where visible |
| S1 record access | `http.request.method == "GET" && http.request.uri contains "/api/records/"` | Request rate, distinct record URLs, one annotated TCP stream |
| S2 documents | `http.request.method == "PUT" && http.request.uri contains "/api/documents/"` | Rate comparison against benign edits and successful responses |
| S3 export | `tcp.port == 9080` | Conversations, duration, HTTP body length, sender and receiver addresses |
| Approved export control | `tcp.port == 9081` | Large approved transfer compared with S3 |
| Network anomalies | `tcp.analysis.retransmission` | Whether retransmission affects wire-volume interpretation |

For each screenshot record the run ID, file name, filter, frame numbers, and observation. Include at least one packet-detail view, one conversation/stream view, and one rate/timing comparison across the submission. Screenshots illustrate saved captures; they do not replace them.

HTTP captures can contain the disposable lab passwords and session tokens. Use credentials created only for this project, retire them after evidence collection, redact screenshots where useful, and keep raw captures in the submission evidence bundle rather than a public source repository. This is compatible with preserving unmodified packet evidence because no real account credential is used.

## Searches and dashboard

Use Discover in Lucene query mode for the filters below; do not confuse these with Wazuh API WQL. Treat field names as a contract to confirm against actual indexed documents. `<RUN_ID>` is a placeholder replaced by an opaque run UUID in the executed export.

| Search | Data view | Filter and output |
|---|---|---|
| Q1 Baseline completeness | `wazuh-archives-*` | `data.service:"hospital-lab" AND data.run_id:"<RUN_ID>"`; count by action, actor, and outcome |
| Q2 Authentication | `wazuh-archives-*` | `data.action:("login_failure" OR "login_success") AND data.run_id:"<RUN_ID>"`; chronological sequence and per-actor failures |
| Q3 Record misuse | `wazuh-archives-*` | `data.action:"record_read" AND data.care_scope:"unassigned" AND data.run_id:"<RUN_ID>"`; actor, patient IDs, timestamps; unique patients |
| Q4 File changes | `wazuh-alerts-*` | `rule.groups:"syscheck" AND agent.name:"hospital-win"`; exact run interval and monitored path filter, table of paths and change details |
| Q5 Exports | `wazuh-archives-*` | `data.action:"export_completed" AND data.run_id:"<RUN_ID>"`; destination approval, bytes, digest, transfer ID |
| Q6 Actionable detections | `wazuh-alerts-*` | `rule.id:(110101 OR 110102 OR 110103 OR 110201 OR 110301 OR 110302) AND data.run_id:"<RUN_ID>"`; rule, level, actor, time |

Q4 has no application run ID. Apply its exact ground-truth interval, agent, and canonical file set; export the saved query with those bounds. In Q1/Q5 explicitly map numeric `data.bytes_sent` and numeric status/duration for aggregation. Confirm whether exact-match fields already are keywords before adding `.keyword`. Save exported mappings and do not invent numeric totals from string fields.

Build one dashboard with eight panels: normal activity by module/action; failed logins over time; record reads by actor and care scope; document updates and native FIM activity; export bytes by approved/unapproved destination; actionable alerts by rule/severity; latest incident table; and collection health. The health panel shows last heartbeat, last indexed event, and agent state. More than 90 seconds without a heartbeat is stale; if no matching event exists, show unknown/no data. Raw FIM counts and burst incidents must have distinct labels.

Dashboard saved objects, queries, data views, and mapping assumptions are deliverables. If the installed dashboard version cannot express a stale-state calculation directly, use a saved query/table with last-seen timestamps and a clearly visible 90-second threshold; do not substitute a green zero-alert indicator.

## Implementation tasks

Commands below are proposed interfaces for code to be built, not commands that already work. `python -m hospital_soc ...` is defined by `src/hospital_soc/__main__.py`. Prefix shell commands with `rtk` when executing in the current Codex workspace; the lab README can show portable commands directly. For each code task, write the named tests, demonstrate failure, implement, rerun, then save a focused commit if Git has been initialized. Do not commit passwords or raw tokens.

### Task 1 Establish and validate the lab

**Owner:** Student 1, with Student 3. **Depends on:** none.

**Files:** `docs/environment.md`, `config/lab.example.json`, `scripts/setup-windows.ps1`, `scripts/setup-linux.sh`, `README.md`.

**Interfaces:** produces validated addresses, absolute runtime roots, exact versions, accessible hospital-port placeholder, and Wazuh dashboard/agent identity `hospital-win`.

- [x] Record OS, available memory/storage, virtualization status, required administrator access, and any existing hypervisor. Preserve existing unrelated services. Evidence: `evidence/environment/host-facts.json`, `docs/environment.md`.
- [ ] Create the VM and host-only network; check subnet collision; install supported Wazuh packages and the Windows agent using official instructions. Record exact versions and installer hashes. Disable NAT after installation.
- [ ] Allocate runtime directories outside OneDrive; restrict firewall bindings; register the agent. Save proof of dashboard access and agent connectivity without exposing credentials.
- [ ] Run a temporary HTTP smoke request across the host-only interface and capture it. Check sender/receiver UTC offset; require no more than one second for cross-host timing claims.
- [ ] Run 15 minutes of basic SOC operation and record memory, swap, CPU, disk, and service stability. If the setup cannot remain responsive, relocate the VM before proceeding.

**Pass:** one stable VM, reachable authenticated dashboard, connected endpoint, verified capture interface, measured clock offset, documented version set. Installation presence alone is not this gate.

### Task 2 Build the hospital service and seed state

**Owner:** Student 1. **Depends on:** Task 1 addressing and paths.

**Files:** `pyproject.toml`, `requirements-lock.txt`, `config.py`, `contracts.py`, `app.py`, `store.py`, `auth.py`, `clinical.py`, `documents.py`, `audit.py`, `__main__.py`; `tests/test_api.py`, `tests/test_audit.py`, `tests/test_paths.py`.

**Interfaces:** `create_app(config: LabConfig) -> Flask`; `seed_lab(config: LabConfig, seed: int) -> dict`; `write_event(event: AuditEvent) -> None`; `update_document(document_id: str, content: bytes, actor_id: str) -> dict`. The app contract owns HTTP status codes and schema above.

- [x] Add tests for successful/invalid sign-in, role rejection, assigned/unassigned reads in both modes, lab order/result persistence, device credential isolation, unique event IDs, and no credential content in audit lines.
- [x] Add path tests for unknown IDs, `..`, absolute paths, missing runtime marker, active reset refusal, and actual Windows junction/hard-link boundaries. Require refusal with no outside file changes. Native symlink/junction detection is shared in the path guard.
- [x] Implement bounded routes, seed generation, SQLite transactions, audit writer, and CLI commands `seed` and `serve`. All 50 files are created before any future FIM baseline. Native FIM setup remains pending.
- [ ] Run `python -m pytest tests/test_api.py tests/test_audit.py tests/test_paths.py -q`; then make live VM-to-host requests for all workflows and verify database/file effects.

**Pass:** actual synthetic records, lab results, device observations, and audit lines agree with responses; no use of canned log generation as a replacement for the service.

### Task 3 Build normal traffic and evidence capture

**Owner:** Student 2, with Student 1. **Depends on:** Task 2.

**Files:** `workload.py`, `scripts/capture.sh`, `tests/test_workload.py`, `docs/protocols.md`.

**Interfaces:** `run_baseline(config: LabConfig, duration_s: int, seed: int) -> RunManifest`; common request receipts contain request ID, action, status, UTC time, and target identity. CLI: `baseline --minutes 30 --seed 101 --run-id <UUID>`.

- [x] Test fixed-seed reproducibility, generated run IDs, failed required-operation status, and separation of receipts/ground truth from monitored logs; actual loopback HTTP exercised. CLI failures return nonzero.
- [x] Implement the baseline mix: clinical reads, occasional login typo, laboratory service exchange, ten device heartbeats every 30 seconds, at most two document edits/minute, and approved exports. Support pausing only document edits during S2 evidence collection. Full-duration runs remain pending.
- [ ] Capture and execute a 30-minute calibration baseline; keep heartbeat/normal workloads running at a controlled rate during attack runs, with separate actor identities.
- [ ] Record capture statistics and verify representative frames for auth, EMR, LIS, and device traffic. Save exact workload rates and event counts.

**Pass:** repeatable normal traffic, a parseable PCAPNG, corresponding audit records, and a documented baseline envelope. Approved-export coverage is completed in Task 7 before holdout evaluation.

### Task 4 Wire Wazuh ingestion and native file evidence

**Owner:** Student 3. **Depends on:** Task 2; can overlap Task 3.

**Files:** `siem/agent-localfile.xml`, `siem/agent-fim.xml`, `siem/manager-archives.md`, `siem/queries.md`, `docs/environment.md`.

**Interfaces:** app events in archives with `data.*`; alerts with `rule.*`; native FIM events with `syscheck.*`; monitored endpoint `hospital-win`.

- [ ] Configure JSON localfile collection and real-time monitoring of the exact existing dummy directory. Run and confirm the FIM initial inventory before mutation tests.
- [ ] Enable JSON archives and Filebeat archive indexing, create archive/alert data views, and verify the timestamp and numeric mappings using a small sample before bulk ingestion.
- [ ] Compare unique server `event_id` values with archived event IDs for a small completed run; require 100% coverage after up to 120 seconds. Identify duplicates separately.
- [ ] Modify one known file, confirm native FIM evidence and path/hash association, then restore it. Save the actual built-in rule IDs rather than assuming them.
- [ ] Interrupt agent collection briefly, generate a known small event set, restore collection, and measure delivery. Confirm the evaluation marks missing events incomplete and the health display becomes stale after 90 seconds. Do not assume an unbounded queue or replay guarantee.

**Pass:** both benign and suspicious events searchable, real FIM events visible, field mappings captured, and telemetry loss visible. [Collection reference](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html).

### Task 5 Implement S1 and tested detection rules

**Owners:** Student 2 scenarios; Student 3 rules. **Depends on:** Tasks 3 and 4.

**Files:** `scenarios.py`, `siem/healthcare_rules.xml`, `tests/fixtures/auth-*.jsonl`, `tests/fixtures/records-*.jsonl`, `tests/test_scenarios.py`.

**Interfaces:** `run_scenario(config: LabConfig, scenario: str, run_id: str, seed: int) -> RunManifest`; scenario IDs `s1`, `s2`, `s3`; CLI `scenario s1 --run-id <UUID> --seed 201`. Produces operation receipts and expected event intervals, never injected detections.

- [ ] Create fixture cases for the exact S1 boundaries and actor/time separation; run them through a fresh `/var/ossec/bin/wazuh-logtest` session per case and save initial failures.
- [ ] Implement base rules and 110101/110102/110103 with native correlation. Verify combined rule behavior on an off-assignment burst, including the event where a higher-severity rule takes precedence.
- [x] Implement the six failures, known-credential success, and 30 distinct off-assignment reads through normal API calls. Fail the scenario if actual responses diverge from expected outcomes. Diagnostic loopback run and actual server-enforcement rerun tested; native alert verification remains pending.
- [ ] Run `python -m pytest tests/test_scenarios.py -q`; validate live ingestion, packet capture, and all expected rule families. Repeat with different opaque run IDs to prove names do not drive detection.

**Pass:** observed responses and records establish the scenario; alert exports and packet evidence support the interpretation; boundary and no-label-leakage tests pass.

### Task 6 Implement S2 and verified recovery

**Owners:** Student 2 scenarios; Student 3 FIM and rule. **Depends on:** Tasks 4 and 5 common runner.

**Files:** `scenarios.py`, `scripts/reset-lab.ps1`, `siem/healthcare_rules.xml`, `tests/test_scenarios.py`, `tests/test_paths.py`, document fixtures.

**Interfaces:** existing `run_scenario(..., scenario="s2", ...)`; `restore_documents(config: LabConfig, seed_manifest: dict) -> dict` returns restored count and digest verification. Reset must stop/refuse concurrent workload and resolve all target paths before mutation.

- [ ] Test 19/20/21 update thresholds, rejected/failed updates, and low-rate legitimate edits. Test restore refuses a root outside the runtime, links, a missing marker, or an active run.
- [ ] Implement 50 manifest-listed harmless updates at one per second and base/110201 detection. Save before/after hashes independently of HTTP receipts.
- [ ] Execute against live native FIM after its baseline is ready, with benign document writes paused. Join every changed file with FIM evidence and available old/new SHA-256 values; wait up to 120 seconds, then declare missing paths incomplete rather than inventing results. An unexpected concurrent write invalidates the attribution and requires a new run.
- [ ] Restore from the seed set and verify all 50 original digests. Record reset events as maintenance outside attack and benign evaluation intervals.
- [ ] Run `python -m pytest tests/test_scenarios.py tests/test_paths.py -q`; preserve live alert/FIM/capture exports and restoration proof.

**Pass:** 50 real changes independently corroborated, 110201 observed, complete restoration, and no mutation outside the dummy root.

### Task 7 Implement S3 and business-policy remediation

**Owners:** Student 1 export/receiver; Student 2 scenario; Student 3 rule. **Depends on:** Tasks 2, 4, and common runner.

**Files:** `exports.py`, `receiver.py`, `scenarios.py`, `siem/healthcare_rules.xml`, `tests/test_exports.py`, `tests/test_exports.py`.

**Interfaces:** `send_export(destination_id: str, payload: bytes, transfer_id: str) -> TransferReceipt`; `create_receiver(config: ReceiverConfig) -> Flask`; receipt fields `transfer_id`, `received_bytes: int`, `sha256: str`, `received_at: str`. CLI receiver command selects approved/unapproved configured port.

- [ ] Test size boundaries, server-derived destination policy, 10 MB maximum, invalid IDs, redirects, receiver refusal, timeouts, incomplete receive, and digest disagreement. Assert no completed-export event on failure.
- [ ] Implement synthetic bundle generation, bounded receiver storage, sender/receiver digest comparison, and rules 110301/110302. Native tests must establish the 1,000,000-byte boundary.
- [ ] Run approved 250 KB and 5 MB controls, an unapproved small transfer, and the exact 5 MB S3 transfer. Capture HTTP and independent receiver receipts.
- [ ] Switch to `enforce` and verify an unapproved export is denied before network transmission; compare the receiver inventory before/after. Run `python -m pytest tests/test_exports.py -q`.

**Pass:** actual sender, receiver, packet, and SIEM evidence agree; approved large transfers avoid the unapproved-destination rules; failures are not misreported as successful transfers.

### Task 8 Build searches dashboard and evaluation

**Owner:** Student 3, reviewed by Students 1 and 2. **Depends on:** Tasks 5–7.

**Files:** `evaluate.py`, `siem/queries.md`, `siem/dashboard.ndjson`, `tests/test_evaluation.py`, `docs/playbooks.md`.

**Interfaces:** `evaluate_run(manifest: RunManifest, artifacts_dir: Path) -> RunMetrics`; output includes `status` (`complete`, `incomplete`, `invalid`), coverage counts, expected/observed rule families, distinct affected objects, latency, and missing evidence. CLI `evaluate --run-dir <PATH>` returns nonzero for incomplete/invalid runs.

- [ ] Test missing logs/PCAP/receipts, missing FIM paths, duplicate events, timestamps with unacceptable clock offset, failed generator operations, and malformed manifests. No absent measurement may default to a passing zero.
- [ ] Execute Q1–Q6 against real data and save results/time ranges. Build/export the eight-panel dashboard. Validate a fresh import rather than relying on one browser's cached layout.
- [ ] Perform a 15-minute full-stack soak with archive indexing, native FIM, capture, receivers, device traffic, dashboard queries, and representative scenario bursts active. Record peak host/VM RAM, swap, CPU, index health, ingestion lag, and packet drops. Require no OOM/service restart, complete app-event reconciliation, working searches, and no unexplained capture loss; use the relocation fallback if unstable.
- [ ] Freeze rules and run three separate benign holdout sessions and three repetitions of each attack. Reconcile ingestion before starting each 65-second quiet interval; record final manager timestamps and run-time capture/collection health.
- [ ] Compute metrics below from ground truth joined to observations. Do not use expected values as observations. If tuning follows a failed holdout, assign a new rule version and rerun a fresh holdout; retain the previous failure.
- [ ] Run `python -m pytest tests/test_evaluation.py -q`; have a different student trace one incident from manifest through packet, source event, alert, query, and dashboard.

**Pass:** executed searches, exported dashboard, traceable metrics, negative controls, and honest incomplete states.

### Task 9 Assemble report and demonstrate reproducibility

**Owners:** all students. **Depends on:** Task 8.

**Files:** `report/Healthcare_SOC_Report.docx`, `docs/demo.md`, `README.md`, finalized evidence bundles and contribution log.

- [ ] Write the report from the evolving evidence: objective/brief interpretation; architecture and protocol stack; normal model; three attack procedures; packet analysis; SIEM configuration/rules/searches; results and limitations; mitigation/recovery; responsibilities; references/reproduction appendix.
- [ ] Include per-scenario procedure, expected indicators, observed events, annotated frames, actual query output, dashboard screenshots, benign comparison, and mitigation result. Label screenshots with exact run IDs/time ranges.
- [ ] Render and visually inspect every report page; verify captions, tables, diagrams, and screenshot readability. Do not treat text extraction as layout verification.
- [ ] Have a second group member rebuild from a clean VM snapshot and a clean runtime, then run all scenarios without relying on the original operator's shell state. Record elapsed time and deviations.
- [ ] Rehearse the demo below, retain an offline evidence copy, verify checksums, and check every rubric row against actual artifacts.

**Pass:** reproducible project, complete technical report, clear individual contributions, and an explainable end-to-end demonstration. All students must be able to explain every component.

## Evaluation and acceptance matrix

| Measure | Definition | Proposed pass target |
|---|---|---|
| Scenario detection | Complete attack runs with the expected rule families / attempted attack runs | 9/9, three repetitions per scenario; incomplete attempts remain reported |
| Application collection | Unique archived app event IDs / unique source app event IDs | 100% for each bounded completed run after 120 s |
| S2 corroboration | Unique mutated file paths supported by native FIM / 50 | 50/50 for each S2 run; complete hash restoration afterwards |
| S3 integrity | Sender bytes/digest equal receiver bytes/digest | Exact agreement for every completed transfer |
| Alert latency | Manager alert time minus the source event time that first satisfies the rule | Target at most 30 s, report each observed value and clock uncertainty |
| Analyst-visible delay | First observed dashboard/index availability minus threshold event time | Target at most 60 s, measured separately from rule firing |
| Benign false incidents | Deduplicated actionable incidents during three independent 10-minute benign holdouts | Target 0 in this small controlled sample; report actual count and duration |
| Packet evidence | Valid capture, expected cross-host flows, acceptable capture loss | Required for every measured run |
| Reproduction | Second student follows documented clean setup/reset and runs cases | No undocumented repair or hidden operator state |

Use incident-level precision and recall only if the matching unit is defined. TP is a correctly matched scenario incident, FP an unmatched actionable incident during the evaluation windows, and FN an attempted positive scenario without the required detection. Precision = TP/(TP+FP); recall = TP/(TP+FN); show numerator and denominator and return not-applicable for an empty denominator. Do not mix file-event counts, rule counts, and incident counts. Report incomplete/invalid runs separately alongside the attempted-run denominator; rerunning them does not erase the first failure. Tiny deterministic trials do not establish production accuracy.

Prefer a per-run table over a single headline percentage. Include scenario/run ID, rule version, expected versus observed alert families, actual request/file/byte counts, missing evidence, latency, benign incidents, and recovery status.

## Team schedule and dependencies

| Week | Student 1 Simulation lead | Student 2 Attack lead | Student 3 Detection lead | Joint milestone |
|---|---|---|---|---|
| 1 | VM/network, app contracts, database/auth, clinical modules | Capture tooling, baseline client, evidence manifest | Wazuh installation, agent/archive/FIM smoke tests | One real event and packet visible end to end |
| 2 | Complete normal workflows and export/receiver | Implement S1/S2/S3 and reset receipts | Implement/test rules and Q1–Q6 | Three scenarios work individually |
| 3 | Fix integration and policy enforcement | Controlled repetitions and negative controls | Dashboard, metrics, collection health | Frozen rules and complete holdout evidence |
| 4 | Rebuild/reproducibility documentation | Evidence annotations and demo rehearsal | Results/limitations and report integration | Rendered report and full group demonstration |

Critical path: Task 1 → Task 2 → Tasks 3/4 → Tasks 5/6/7 → Task 8 → Task 9. Task 7 development can overlap Tasks 5/6 once the API/receipt schema is frozen. Budget roughly 75–105 total student-hours; protect the final quarter for evaluation/report/recovery, not extra features.

If time contracts, remove optional UI, extra device protocols, HTTPS comparison, and multi-VM expansion first. Preserve all three attacks, real baseline activity, native FIM, packet evidence, executed SIEM queries, dashboard, and report.

## Demonstration and analyst response

Suggested 12–15 minute demonstration: two minutes architecture/normal workflow; three minutes S1 and evidence; three minutes S2 plus hash/FIM corroboration; two minutes S3 and receiver proof; two minutes dashboard, metrics, remediation, and limitations. Allow ingestion time visibly. Use previously captured runs as a labeled fallback when needed; never present replay as live detection.

For each incident: identify affected fictional asset/user; validate raw evidence; check benign explanations; state confidence and missing data; choose a manual containment action; apply the lab mitigation where implemented; verify recovery; close with a documented outcome. S1 focuses on account and care access, S2 on document integrity/recovery, and S3 on export policy and destination control.

Risks and responses: VM memory pressure → validate early or relocate; capture on wrong interface → smoke-test every capture; normal logs absent → validate archive indexing; FIM baseline/queues incomplete → pre-seed and reconcile paths; rule inheritance/threshold mismatch → sequence/boundary tests; clock drift → measure offset and qualify latency; OneDrive interference → keep live runtime outside sync; healthcare overclaim → clearly label simplified protocols and synthetic workflows.

## Final submission checklist

- [ ] Topic registered and healthcare interpretation of generic task wording recorded.
- [ ] Architecture diagram and actual protocol-stack discussion match the implementation.
- [ ] Setup, versions, environment, dependencies, reset, and second-student reproduction documented.
- [ ] All four hospital domains produce real normal activity and searchable telemetry.
- [ ] Three attacks have procedures, ground truth, baseline comparison, and real evidence.
- [ ] Wireshark PCAPNG files, filters, annotated frames, and observations are included.
- [ ] Native FIM and before/after/restored hashes support S2; independent receiver evidence supports S3.
- [ ] Executed SIEM searches, rules, alert exports, dashboard objects, and screenshots are included.
- [ ] Results include failures, collection gaps, benign controls, timing, and limitations.
- [ ] Mitigations and observed policy/recovery reruns are distinguished from recommendations.
- [ ] Final report is rendered and inspected; all students can explain the whole project.

## Source notes

Primary requirements come from the local Project.docx, read on 22 October 2026. Official technical references were consulted during planning; implementation must check them against the pinned installed versions. Core references are linked beside the relevant decisions above. Additional references: [Flask application testing](https://github.com/pallets/flask/blob/3_1_1/docs/testing.rst), [Wazuh FIM settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html), [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html), [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/index.html), and [HHS voluntary healthcare cybersecurity goals](https://hhscyber.hhs.gov/cybersecurity-performance-goals.html). Healthcare goals provide context; this project does not demonstrate compliance certification or clinical safety validation.
