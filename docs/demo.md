# Healthcare SOC demonstration

## Evidence-backed rehearsal route

Use the private measured-20261113 campaign and report/evidence-index.md. The group rehearsal itself is pending; record it in docs/task9-signoff.md. Prepare the verified dashboard export, six query exports, the native26-case proof and a local copy of this report before presenting.

| Time | Demonstrator shows | Evidence |
|---|---|---|
| 0–2 min | Host/guest topology and normal workload | Report architecture, calibration manifest and Q1 |
| 2–5 min | Six failures, successful login, thirty off-assignment reads; enforce denial | 06-s1-1, Q2/Q3/Q6 and 15-s1-enforce |
| 5–8 min | Fifty file changes, independent FIM hashes and seed restoration | 12-s2-1 / live-revalidation-20261114 S2 runs, Q4 and timestamped restore receipts |
| 8–10 min | Exact 5 MB receiver object and blocked unapproved export | 09-s3-1, Q5 and 16-s3-enforce |
| 10–13 min | Eight dashboard panels, FRESH/STALE/UNKNOWN and recovery | dashboard-exported.ndjson, final screenshots and interruption-recovery.json |
| 13–15 min | Per-run metrics, clean rebuilding and limitations | Evidence audit and task9-signoff |

For packet discussion open a representative frame listed in the report, show request method/URI, host-only addresses and response status, and conceal credential headers. Use a separate lab-only credential set for any fresh live demonstration. Mark saved screenshots and captures as recorded evidence. Recorded native26/26 and current local tests are distinct observations.

Use only evidence whose run ID, rule revision and timestamps are known. Begin with the architecture, simulated modules and the distinction between code tests and live Wazuh evidence.

In 12–15 minutes show normal records, lab/device activity and searchable baseline; S1 failures and unassigned reads; S2 actual before/after/FIM hashes plus recovery; S3 sender/receiver agreement and destination policy; then the six searches, eight dashboard panels and measurement limitations. Label any previously captured replay instead of presenting it as live detection.

Each student explains one primary component and answers questions about the full data path. Final report screenshots must point to saved PCAPNG frames, actual query exports and the measured run manifest. Synthetic file updates are not execution of real ransomware, the JSON API does not implement HL7/FHIR/DICOM, and the one-subnet lab does not demonstrate production segmentation.
