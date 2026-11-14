# Independent evidence index — 14 November 2026

The audit reads preserved evidence without changing raw artifacts or source. `PRIVATE_EVIDENCE` means the operator's private `HealthcareSOCLab/evidence` directory. Private paths, host usernames, credentials and raw event payloads are excluded from this index. The machine-readable results are in `report/evidence-verification.json`.

## Acceptance boundary

The 14 observe-mode runs retain original `complete` metrics on Ubuntu `tshark 4.2.2`. In the initial November 14 pre-compat audit on Windows `tshark 4.6.9`, exact CSV string comparison marked all 16 evaluated runs `incomplete` solely because `4.6.9` populates `http.request.uri` on pure HTTP response rows (`http.response.code != ""`, `http.request.method == ""`) while `4.2.2` left that column empty (explicitly isolated nonpacket rechecks reproduced all saved metrics). After adding strict reverse-4-tuple paired-request equivalence in `src/hospital_soc/packets.py` (`0` unexpected column/row differences across all 18 captures, `52,451` CSV data rows, and `2,562` response rows), a separate replay in `PRIVATE_EVIDENCE/replay-20261114-tshark469` using real Windows `tshark 4.6.9` evaluates all 14 observe-mode runs (`01–14`) as `complete` (`issues: []`), leaves `15–16` `incomplete` for expected enforce mitigation review, and marks `17–18` `incomplete` under the general observe evaluator for missing `observations.json`, `native-rule-tests.json`, and workload intent (plus general 5 MB/`110302` expectations on 250 KB control `18`) while both pass their scoped `control-summary.json` checks and record `0` packet verification errors (`replay-summary.json` SHA-256 `20a21133f5b673ccce0f2572e60dd7180d1b2bd5a7367b6531cf65c03e39e7a5`). Both the historical pre-compat incomplete record and the untouched `measured-20261113` bundle are preserved.

The preserved native proof, application/archive joins, FIM digests, received objects, Windows `tshark 4.6.9` compatibility replay, final screenshots, and November 14 live revalidation (`PRIVATE_EVIDENCE/live-revalidation-20261114`, `318` files, `SHA256SUMS.txt` SHA-256 `8b41d5e67e7fed85a3566fbfb83e1c79b62fe81caa568552b4e6c17c9a4a6d0c`) substantiate substantial lab results. On November 14, live revalidation executed `01-soak-15m-revalidated` (`complete` after fixing a midnight UTC `data.service` mapping collision captured in preserved `01-soak-15m-replacement`), UTC-bounded `Q2_s1_1`/`Q3_s1_1` re-exports, three revalidated S2 runs (`12..14-s2-revalidated-*`), and five timestamped 50/50 reset receipts. Un-rerun November 13 runs (`02-calibration-30m`, `03..05` holdouts, `06..08` S1, `09..11` S3, `15..16` enforce, `17..18` controls) retain historical post-run clock bounds, and Windows `WazuhSvc`/15-minute disconnect testing remains disclosed unexecuted Administrator-only scope rather than a submission gate. Separate clean-VM retesting by other group members has been waived per project scope decision; optional contribution names and demo rehearsal notes remain in `docs/task9-signoff.md`.

## Inventory and provenance

| Evidence | Independently checked | Result |
|---|---|---|
| `measured-20261113/SHA256SUMS.txt` | Every listed file's actual SHA-256 | 860/860 match; no mismatch |
| Listed evidence size | Actual listed file sizes | 155,720,509 bytes; 148.50665 MiB |
| Entire present campaign tree | Files and sizes | 874 files; 156,586,359 bytes |
| Supplemental images and summaries | Actual SHA-256 recorded by this audit | 13 screenshot/summary files are outside the original manifest; manifest itself also unlisted |
| Native suite root | Rule hash, revision, all transcript hashes and per-event sequences | Schema 3; 26/26 verified |

Native root: `PRIVATE_EVIDENCE/native-rule-proof-20261113T193310Z`. Recorded engine is Wazuh v4.14.10. Rules SHA-256 is `8a71944c501ec8a0b15ccb7c910c96e762f71976ad0be1da49512397fb5eb4bb`; recomputed loaded revision is `db7629b4d71476b5d26f0d98cd2e6c80620dd1fec2f1cfc2becb83da19ada6f7`. All 16 evaluated campaign runs carry independently verified copies of the proof.

Expiry transcripts reconstruct distinct sessions and actual engine-time gaps of 65.002, 65.001 and 65.001 seconds. Preserved configuration/executable snapshot hashes have the required shape; their live VM files were not accessed. Matching hashes establish consistency with these preserved files, not a signature or independent proof of their original collection.

## Windows and Ubuntu live evidence copy provenance

The canonical finalized submission copy is **Windows `PRIVATE_EVIDENCE/live-revalidation-20261114`**. Read-only comparison on 14 November verified all **318/318** listed Windows hashes. The retained Ubuntu copy carries the same `SHA256SUMS.txt` (`8b41d5e67e7fed85a3566fbfb83e1c79b62fe81caa568552b4e6c17c9a4a6d0c`) but matches **311/318** raw hashes. Both original copies and the manifest remain unchanged.

All seven byte differences are serialization differences: the five `metrics.json` files use CRLF plus a terminal newline on Windows versus LF without a terminal newline on Ubuntu; the two visibility-poll files differ only in CRLF versus LF. Replacing line endings and removing at most one terminal LF **in memory** produces identical bytes in every case. Parsed JSON values are identical, including every timestamp, event ID, poll result and evaluator verdict. No measurement or acceptance result changes. This comparison does not convert the Ubuntu raw-hash failures into passes or remove the historical timing qualifications.

| Relative path within `live-revalidation-20261114` | Windows bytes | Ubuntu bytes | Difference |
|---|---:|---:|---|
| `01-soak-15m-replacement/metrics.json` | 509 | 489 | CRLF versus LF plus one terminal newline on Windows |
| `01-soak-15m-revalidated/metrics.json` | 452 | 434 | CRLF versus LF plus one terminal newline on Windows |
| `12-s2-revalidated-1/metrics.json` | 512 | 487 | CRLF versus LF plus one terminal newline on Windows |
| `13-s2-revalidated-2/metrics.json` | 512 | 487 | CRLF versus LF plus one terminal newline on Windows |
| `14-s2-revalidated-3/metrics.json` | 512 | 487 | CRLF versus LF plus one terminal newline on Windows |
| `14-s2-revalidated-3/visibility-polls-m1.json` | 1038 | 997 | CRLF versus LF only |
| `14-s2-revalidated-3/visibility-polls-m2.json` | 1478 | 1419 | CRLF versus LF only |

Exact Windows/manifest and Ubuntu SHA-256 values for all seven paths are recorded in `report/evidence-verification.json` under `live_revalidation_20261114.copy_provenance`. The Ubuntu copy is retained as a content-equivalent source copy, not a byte-identical copy of the finalized Windows submission. No file is overwritten to make the hashes agree.

## Run ledger

Each run prefix below resolves under `PRIVATE_EVIDENCE/measured-20261113/`. Counts are independently joined by run/event identity; packets are actual structural PCAPNG counts. Every evaluated run records zero packet drops. Detection rules are raw custom alert families; raw alert counts are not incident counts.

| Run | Scenario | Source/archive | Packets | Rules / content corroboration | Saved status |
|---|---|---:|---:|---|---|
| `01-soak-15m` | Baseline 15 min | 760/760 | 6,937 | No actionable alert | complete |
| `02-calibration-30m` | Baseline 30 min | 1505/1505 | 13,787 | No actionable alert; 15/15 LIS pairs; 600 telemetry events | complete |
| `03-holdout-1` | Baseline 10 min | 509/509 | 4,156 | No actionable alert | complete |
| `04-holdout-2` | Baseline 10 min | 509/509 | 4,299 | No actionable alert | complete |
| `05-holdout-3` | Baseline 10 min | 509/509 | 4,151 | No actionable alert | complete |
| `06-s1-1` | S1 observe | 39/39 | 470 | 110101, 110102, 110103 | complete |
| `07-s1-2` | S1 observe | 39/39 | 472 | 110101, 110102, 110103 | complete |
| `08-s1-3` | S1 observe | 39/39 | 470 | 110101, 110102, 110103 | complete |
| `09-s3-1` | S3 observe | 5/5 | 3,654 | 110302; actual 5,000,000-byte receiver object SHA-256 matches | complete |
| `10-s3-2` | S3 observe | 5/5 | 3,660 | 110302; actual receiver object matches | complete |
| `11-s3-3` | S3 observe | 5/5 | 3,606 | 110302; actual receiver object matches | complete |
| `12-s2-1` | S2 observe | 105/105 | 758 | 110201; 50/50 application/inventory/FIM digest joins | complete |
| `13-s2-2` | S2 observe | 105/105 | 758 | 110201; 50/50 digest joins | complete |
| `14-s2-3` | S2 observe | 105/105 | 760 | 110201; 50/50 digest joins | complete |
| `15-s1-enforce` | S1 enforce | 39/39 | 470 | 110101 only; six 401 logins and thirty 403 record reads | incomplete control |
| `16-s3-enforce` | S3 enforce | 4/4 | 40 | Export request 403; no successful export; no custom alert | incomplete control |
| `17-s3-approved-5mb` | Approved destination control | 5/5 | 3,687 | No custom alert; actual receiver object matches (`control-summary.json` pass) | Scoped control pass; general replay: incomplete (missing obs/native/intent) |
| `18-s3-unapproved-250kb` | Size control | 5/5 | 316 | 110301 only; actual receiver object matches (`control-summary.json` pass) | Scoped control pass; general replay: incomplete (missing obs/native/intent & 250 KB scope) |

All 18 captures under `PRIVATE_EVIDENCE/measured-20261113/` total `52,451` CSV data rows (`0` dropped packets on `ens192`). All evaluated runs have 100% source/archive ID coverage and no duplicate archived run IDs. All 15 recorded predecessor links match the actual preceding run's final manager timestamp; recorded quiet intervals span 76.296–272.568 seconds, exceeding 65 seconds. The initial soak is explicitly the first run.

Calibration plus the three holdouts comprise the cited 60 benign minutes with no actionable alerts. The separate 15-minute soak is additional. All nine November 13 attack repetitions (`06–14`) show their expected alert families (`0.119–1.951 s` rule latency range across those measured November 13 attack alerts; November 14 revalidated S2 runs `12..14-s2-revalidated-*` span `0.077–1.913 s`). These are finite synthetic trials and do not establish production sensitivity or a general false-positive rate.

## Run UUID and UTC window locator

### Preserved campaign — 13 November 2026 (`PRIVATE_EVIDENCE/measured-20261113`)

| Run | Run ID (UUID) | Scenario / mode | UTC window (`manifest.started_at` – `manifest.ended_at`) |
|---|---|---|---|
| `01-soak-15m` | `4f6116c0-11e3-4275-8d52-337c2b516d0d` | `baseline / observe` | `2026-11-13T19:44:27.068Z` – `2026-11-13T19:59:27.072Z` |
| `02-calibration-30m` | `d35d222c-6286-4b21-877a-109a5a96dd2c` | `baseline / observe` | `2026-11-13T20:02:04.686Z` – `2026-11-13T20:32:04.689Z` |
| `03-holdout-1` | `3266019d-91ee-4c6a-bf9e-3bfb707b820c` | `baseline / observe` | `2026-11-13T20:34:00.116Z` – `2026-11-13T20:44:00.118Z` |
| `04-holdout-2` | `a2d9907c-bc26-4349-b48d-ffc2ea3e61ea` | `baseline / observe` | `2026-11-13T20:45:02.942Z` – `2026-11-13T20:55:02.944Z` |
| `05-holdout-3` | `f747ab41-5eb4-4681-997a-af4e3cd4add7` | `baseline / observe` | `2026-11-13T20:56:06.069Z` – `2026-11-13T21:06:06.070Z` |
| `06-s1-1` | `e4570e23-7c0a-4490-9861-b9f29405b9c3` | `s1 / observe` | `2026-11-13T21:10:24.110Z` – `2026-11-13T21:11:42.151Z` |
| `07-s1-2` | `4d4c8d67-e3e0-4a0b-be5e-43a766b0a0b7` | `s1 / observe` | `2026-11-13T21:12:57.147Z` – `2026-11-13T21:14:15.295Z` |
| `08-s1-3` | `6c4349c8-3cc1-4fc2-805f-7f81720804d9` | `s1 / observe` | `2026-11-13T21:15:31.961Z` – `2026-11-13T21:16:49.843Z` |
| `09-s3-1` | `d62b2c3d-f8c5-4987-b33f-d57636e924ac` | `s3 / observe` | `2026-11-13T21:18:04.770Z` – `2026-11-13T21:18:05.252Z` |
| `10-s3-2` | `8316fd35-d5c7-458f-b563-84279eca1555` | `s3 / observe` | `2026-11-13T21:19:23.159Z` – `2026-11-13T21:19:23.689Z` |
| `11-s3-3` | `52f44b82-8fe1-4124-8c92-f8a23a083a8d` | `s3 / observe` | `2026-11-13T21:20:41.581Z` – `2026-11-13T21:20:42.133Z` |
| `12-s2-1` | `723e82b0-d45d-4ede-8586-ee3f017ef817` | `s2 / observe` | `2026-11-13T21:22:21.742Z` – `2026-11-13T21:23:13.412Z` |
| `13-s2-2` | `a1cdbe21-aa26-4419-a1c0-2dc28899e598` | `s2 / observe` | `2026-11-13T21:27:17.629Z` – `2026-11-13T21:28:10.028Z` |
| `14-s2-3` | `416054dc-5b21-424e-ba00-0b69dff1b09c` | `s2 / observe` | `2026-11-13T21:32:17.416Z` – `2026-11-13T21:33:09.846Z` |
| `15-s1-enforce` | `0a38dcd6-51c0-4b17-ba7a-1f1972ff97d7` | `s1 / enforce` | `2026-11-13T21:37:23.821Z` – `2026-11-13T21:38:42.375Z` |
| `16-s3-enforce` | `78b0ba96-ebe0-4208-ba46-3f3a0bccbb3f` | `s3 / enforce` | `2026-11-13T21:39:58.362Z` – `2026-11-13T21:39:59.049Z` |
| `17-s3-approved-5mb` | `6c6f763b-811d-44d5-b3b3-9dd5e257bb26` | `s3 / observe (approved control)` | `2026-11-13T21:43:18.862Z` – `2026-11-13T21:43:19.503Z` |
| `18-s3-unapproved-250kb` | `3f2c44b6-b109-4518-a9b3-72b3d003766b` | `s3 / observe (250 KB control)` | `2026-11-13T21:44:37.263Z` – `2026-11-13T21:44:37.821Z` |

### Live revalidation — 14 November 2026 (`PRIVATE_EVIDENCE/live-revalidation-20261114`)

| Artifact / run | Run ID (UUID) / scope | Role / outcome | UTC window / timestamp |
|---|---|---|---|
| `01-soak-15m-replacement` | `c7e19902-a86c-4b0c-806b-d4c8637c3682` | Failed soak diagnostic (`incomplete`, 0/760 indexed) | `2026-11-14T08:30:05.359Z` – `2026-11-14T08:45:05.363Z` |
| `01-soak-15m-revalidated` | `de22c9fc-82a9-40b0-82c8-35f685c7017f` | Replacement soak (`complete`, 760/760 indexed) | `2026-11-14T08:52:01.105Z` – `2026-11-14T09:07:01.110Z` |
| `12-s2-revalidated-1` | `4db0b64a-ba2a-4fb9-9834-2886d9390f8b` | Revalidated S2 rep 1 (`complete`, 50/50 FIM) | `2026-11-14T09:10:44.802Z` – `2026-11-14T09:11:39.877Z` |
| `13-s2-revalidated-2` | `226eb296-1c7f-43b7-9651-4a9fc19c8720` | Revalidated S2 rep 2 (`complete`, 50/50 FIM) | `2026-11-14T09:16:18.089Z` – `2026-11-14T09:17:10.400Z` |
| `14-s2-revalidated-3` | `83168e5e-d388-4d56-8852-61174c4907f1` | Revalidated S2 rep 3 (`complete`, 50/50 FIM) | `2026-11-14T09:22:32.872Z` – `2026-11-14T09:23:25.634Z` |
| `query-results/Q2_s1_1`, `Q3_s1_1` | `e4570e23-7c0a-4490-9861-b9f29405b9c3` | UTC-bounded `06-s1-1` queries (`7/7`, `30/30`) | `gte 2026-11-13T21:10:24.110Z`, `lte 2026-11-13T21:13:42.151Z` |
| `restore-receipts/reset-pre-serve-20261114.json` | Seed `101`, `50/50` verified | Pre-serve reset receipt | `2026-11-14T08:12:41.475111+00:00` |
| `restore-receipts/pre-s2-1-reset.json` | Seed `101`, `50/50` verified | Pre-S2 rep 1 reset receipt | `2026-11-14T09:08:37.352501+00:00` |
| `restore-receipts/post-s2-1-reset.json` | Seed `101`, `50/50` verified | Post-S2 rep 1 reset receipt | `2026-11-14T09:13:20.596929+00:00` |
| `restore-receipts/post-s2-2-reset.json` | Seed `101`, `50/50` verified | Post-S2 rep 2 reset receipt | `2026-11-14T09:20:32.367833+00:00` |
| `restore-receipts/post-s2-3-reset.json` | Seed `101`, `50/50` verified | Post-S2 rep 3 reset receipt | `2026-11-14T09:26:08.475541+00:00` |

## Timing, capacity and restoration limits

Clock files contain post-run RTT/offset samples. Their bounds reconcile arithmetically to observations within rounding and span 231.70–322.33 ms, but samples were taken 62.78–770.11 seconds after run completion. They do not establish continuous synchronization throughout each run. Alert latencies are source-to-manager timestamp differences with this clock limitation.

For runs 02–16, phase summaries record source-to-index visibility of 8.887–19.840 seconds. These observations are not independent per-event index-poll receipts. The soak's 1.959 seconds is explicitly a source/manager timing proxy obtained from a final collection sweep after a TShark segfault. Its PCAPNG is structurally valid with 6,937 packets and recorded zero drops; the segfault and measurement substitution remain limitations.

Calibration's 122 resource samples span 1,827.646 seconds: available memory 5,055.82–5,112.49 MiB, maximum swap used 0 KiB, maximum one-minute load 0.2681, minimum free disk 31.0 GiB, and 122/122 healthy HTTP observations. Soak resource data is a post-run snapshot, not continuous 15-minute polling.

All three S2 pre-run inventories equal seed digests. Current runtime document files independently match seed hashes 50/50. No separately timestamped per-run restoration receipt exists in this measured directory, so exact historical restoration timing is not independently certified.

## Query and dashboard evidence

| Evidence under `query-results/` | Independent reconciliation | Scope limit |
|---|---|---|
| `Q1_calibration.json`, `Q1_s1_1.json` | 1,505 and 39 run-scoped source events agree with query aggregates | Explicit time bounds; aggregate-only exports preserve no per-event query hits |
| `Q2_s1_1.json` | Seven authentication hit event IDs join to raw source | Run UUID scope; no explicit time bounds |
| `Q3_s1_1.json` | Thirty unassigned read hit event IDs join; thirty distinct patients | Run UUID scope; no explicit time bounds |
| `Q4_s2_1.json`, reconciled CSV | 50 before/after digest rows agree; native FIM corroborated against raw run evidence | One S2 repetition's query export |
| `Q5_s3_all_runs.json`, reconciled CSV | Eleven actual receiver files verify size and SHA-256; 21,750,000 total bytes | Six selected runs: calibration, three S3 repetitions, two boundary controls; not every campaign export |
| `Q6_campaign_alerts.json` | 104 raw actionable alert documents across run evidence | Raw document count, not incident count |

`dashboard-exported.ndjson` contains eight unique panel references, each version `7.10.0`, a 10,000-ms enabled refresh interval and `now-4h` restored time range. The final `screenshots/dashboard-fresh.png` visibly renders all eight panels and a green FRESH banner. Final panel crops and empty-query/future-clock screenshots substantiate FRESH and UNKNOWN rendering. STALE snapshots are preserved. The browser summary has 40 nested selector matches that repeat eight actual panels. It does not show 40 panels.

Use the final dashboard and `panel-35-fresh.png`/`panel-36-fresh.png` screenshots. `crop-dashboard-fresh.png` and `crop-dashboard-stale.png` are older pre-patch warning crops and must not be presented as the final rendering. The configured refresh and before/after screenshots support the operator account; no independently timed continuous recording certifies the claimed live ten-second transition. The four-hour dashboard covers broader activity than the six-run Q5 subset, so its totals need not equal that reconciliation.

## Controls and recovery

The S1 enforce manifest independently records six 401 responses and thirty blocked record reads (403), with only the authentication alert family. The S3 enforce manifest records a 403 export request and no successful export in source. The operator's preserved receiver before/after hash dictionaries are equal. The approved 5 MB control has no custom alert; the unapproved 250 KB control has only 110301, and both actual received objects match.

`interruption-recovery.json` records a filebeat-queued heartbeat indexed seven seconds after restart and a manager-outage heartbeat recovered from agent buffering. These are preserved operator summary records; this audit did not recreate outages or obtain independent raw per-stage index response receipts. Non-admin Windows service-stop and the manager's 15-minute disconnect timeout limitations remain as documented.

## Live revalidation — 14 November 2026 (`PRIVATE_EVIDENCE/live-revalidation-20261114`)

- **Closed gaps vs preserved history:** `01-soak-15m-revalidated` (`de22c9fc-82a9-40b0-82c8-35f685c7017f`) supersedes the soak proxy with `17` periodic `/health` clock samples across the run+drain collection window (`14` strictly inside `manifest.started_at..ended_at`, `max 61.42 ms`), `17` `/proc` samples (`0` OOM, `0` swap), `760/760` archived & indexed events (`1.828–11.943 s` source-to-index), `6,574` packets (`0` drops), and `3` live `0.5 s` OpenSearch `data.event_id` milestone polls (`5.389–7.985 s`). Preserved failure `01-soak-15m-replacement` (`c7e19902`, `0/760` indexed) and `failure-diagnostics/` document the `2026-11-14` UTC rollover `syscollector` `data.service` Object mapping collision and its remediation (`keyword` template pinning + `10,091/10,091` migrated docs). Live UTC-bounded `Q2_s1_1` (`7/7`) and `Q3_s1_1` (`30/30`, `30` distinct patients) exports (`gte: 2026-11-13T21:10:24.110Z`, `lte: 2026-11-13T21:13:42.151Z`, `0` mismatches) and three `complete` S2 repetitions (`12..14-s2-revalidated-*`, `50/50` FIM digests, `110201` latencies `0.077–1.913 s`, periodic clocks `<= 57.27 ms` across `9/13/13` run+drain samples with `3` strictly inside each workload window, `0` packet drops) bracketed by 5 timestamped 50/50 `restore-receipts/` JSON files close the S2/query/soak timing gaps while preserving `measured-20261113`.
- **Timing & polling collector qualification:** In `live-revalidation-20261114`, `per-event-index-visibility.jsonl` was recorded by Ubuntu `run_reval.py` immediately after each `>= 1.0 s`-cadence OpenSearch query returned, whereas `visibility-polls*.json` milestone records (`m1..m3` soak, `m1..m2` S2) came from `visibility_probe.py` calling the pre-fix `poll_first_index_visibility` helper (which stamped `polled_at_utc` and `first_visible_utc` at poll-request start with unmeasured HTTP/OpenSearch query duration). Saved November 14 timing values therefore represent discrete polling observation bounds with unmeasured query duration (or `~1 s` loop cadence), not internal OpenSearch commit instants, and periodic clock samples do not establish continuous synchronization across inter-sample gaps. Subsequent prospective fixes in `src/hospital_soc/timing.py` and `scripts/measure-run-timing.py` do not alter or recalculate preserved November 14 evidence files. Detection, `100%` collection, FIM digest joins, receiver integrity, and packet verification stand independently of polling-precision bounds.
- **Remaining boundaries (teammate retesting waived):**
  - Un-rerun November 13 intervals (`02-calibration-30m`, `03..05` holdouts, `06..08` S1, `09..11` S3, `15..16` enforce, `17..18` controls) were not re-executed and retain post-run clock bounds (`pending` only if per-interval contemporaneous clocks were required across every historical run).
  - Task 4's planned collection interruption and >90 s stale health display were exercised on guest services in `interruption-recovery.json`. Stopping `WazuhSvc` on Windows and observing the native `active -> disconnected -> active` transition under `<agents_disconnection_time>15m</agents_disconnection_time>` requires an Administrator shell (`IS_ADMIN=False` here) and remains disclosed as unexecuted Administrator-only scope rather than a submission gate.
  - Separate clean-VM retesting by other group members has been waived per project scope decision (`docs/clean-rebuild.md` remains as the reference procedure, with automated isolated packaging checked via `scripts/check-clean-install.py`); record optional group contribution names and rehearsal notes in `docs/task9-signoff.md`.
