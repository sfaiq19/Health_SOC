# Diagnostic evidence audit · 13 November 2026

The private handoff archive was checked offline on Windows. Its SHA-256 was `79b51a408ba21c1ab4894817996b99f92397b6cf55714bcb4a977aab3914bd40` (352,518 bytes, 79 regular files, 8 directories). The audit used a temporary directory under the private handoff folder. The packet export contains authorization headers. Keep the archive, captures, CSVs and transcripts in private storage.

## Three observe-mode trials

| Run ID | Source / manager / client receipts | Reconciled alerts | PCAPNG frames / bytes / reported drops |
|---|---|---|---|
| S1 `46c307ea-b2df-403f-b0d5-dffdef3db08b` | 39 / 39 / 38 | 110101 × 1, 110102 × 29, 110103 × 1 | 471 / 73,820 / 0 |
| S2 `7851a98e-98a4-48c2-9e0f-18dce485f80b` | 105 / 105 / 54 | 110201 × 2, plus 50 native 550 file modifications | 756 / 183,688 / 0 |
| S3 `d7d06719-7058-441a-ad0e-629aa3d28a39` | 5 / 5 / 3 | 110302 × 1 | 3,800 / 5,338,340 / 0 |

All 149 source IDs matched manager archives without duplicates. The matching records and custom alerts agreed on run ID, event ID, request ID, action, outcome, actor ID, actor key and source time. Every match came from agent `001` / `hospital-win`. The PCAPNG frame counts agree with the dumpcap summaries for `ens192`. Run-tagged requests include 30 S1 record GETs, 50 S2 document PUTs and one S3 receiver POST between the two host-only addresses.

**S2.** All 50 rule-550 records include `syscheck.sha256_before` and `sha256_after`. Each original hash differs from its replacement. Both hashes agree with the corresponding inventory, application source and client receipt. Each record has a distinct canonical Windows path under the configured document root, identifies the expected agent and falls in the collection window. The original evaluator reported **0/50** because Wazuh emitted lowercase basenames such as `d001.txt` and the inventory uses `D001`. These are the same Windows file. Canonicalizing the *complete* expected paths must still reject duplicates, alternate roots and incompatible digests.

**S3.** The application, generator receipt and independent receiver receipt agree on the transfer ID, byte count and SHA-256. An in-memory TShark reassembly of the one POST to port 9080 yielded 5,000,000 bytes with the same SHA-256. The capture contains a 201 response from port 9080. The sender-facing client receipt reported 200. The archive contains no receiver-side `received/<transfer_id>.bin`, so the evaluator correctly counted **0 verified receiver objects**. Copy the original receiver file during formal collection.

**Packet export.** The Windows TShark 4.6.9 fresh export and archived Ubuntu 4.2.2 CSV agreed on every request row and on parsed frame counts. The only differing field was `http.request.uri` on 38 S1, 54 S2 and 4 S3 response rows. The archived response rows have an empty URI and the Windows re-export populates it. Exact export comparison therefore failed on all three. Record the TShark build and evaluate with the same build and settings used for export. Preserve the original CSV.

## Historical native proof

The archived Ubuntu candidate and proof XML were byte-identical, SHA-256 `8a71944c501ec8a0b15ccb7c910c96e762f71976ad0be1da49512397fb5eb4bb`. That digest also agrees with the installed-rules entry in the proof snapshot. The content-derived revision in the XML and loaded-revision challenge was `db7629b4d71476b5d26f0d98cd2e6c80620dd1fec2f1cfc2becb83da19ada6f7`.

Reparsing all 26 transcripts from Wazuh 4.14.10 reproduced the stored results for all **351** per-event classifications. **23/26 passed.** The only mismatches were event 5 of auth-expiry (110001 expected, 110101 observed), event 20 of reads-expiry (110002 / 110103) and event 20 of writes-expiry (110003 / 110201). All earlier events in those cases received their base classification. Each expiry case used a single actor and distinct input event IDs. The auth inputs said `action=login_failure` and `outcome=success`. The 45 expiry inputs had no event timestamps. The transcripts establish classification order but supply no per-input engine processing or acknowledgement times.

The separate live-auth archive has six distinct failed-login event IDs for one actor. Agent 001's six manager archive records each have rule 110001. The supplied alerts file is empty. The last two inter-event gaps on the **manager clock** were 74.377 and 32.874 seconds. The largest 60-second window contained four events. This checks auth expiry for that sequence. Its bundle omits the original source file, and its decoded events have no run or request IDs. Reads and writes have no corresponding live-manager expiry evidence in the archive.

## Acceptance boundary

The original evaluator reported **incomplete** for all three runs. Each diagnostic directory lacks `observations.json`, `native-rule-tests.json` and `healthcare_rules.xml`. The separate historical native proof failed. The diagnostics establish observed detection and source coverage for the three listed trials. Clock offset, time to first index visibility, bounded collection confirmation and inter-trial drain require contemporaneous observations. Formal stability, calibration, holdouts, attack repetitions, dashboard validation, report and rebuild remain open.
