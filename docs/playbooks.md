# Analyst response playbooks

## Account misuse and record access

Inspect failures, success and reads by authenticated actor and socket IP. Confirm care assignment from the server, the number of distinct records, timing, and whether access returned content. A failed login identifies an attempted account, not an authenticated person. Consider ordinary typos and legitimate high-volume clinical work. In the lab, enable care enforcement, repeat the unassigned reads and verify 403 responses with no record content. Recommend MFA and session investigation without claiming those features are implemented here.

## Rapid document changes

Compare source write events, the real file inventory and independent native FIM digests. Packet PUT bursts establish traffic, not ransomware execution. Stop the workload and service before restoring the 50 dedicated dummy files. Restore through the checked CLI and verify all seed hashes. Keep maintenance events outside evaluation windows. In a real clinical context containment must be coordinated with continuity and safety owners; this prototype performs no automatic device isolation.

## Unapproved export

Verify sender completion against receiver logs, object size and digest. Distinguish the hospital business allowlist from the lab's safety allowlist: the unapproved business receiver is still an authorized lab-only endpoint. Investigate the record-clerk session and destination. Enable destination enforcement, repeat, and confirm denial plus unchanged receiver inventory. TCP wire volume includes overhead and retransmissions and differs from body size.

## Incomplete observations

Missing archives, stale heartbeat, disconnected agent, missing packets, or failed generators make the run incomplete/invalid. Preserve failed attempts, repair collection, drain prior events, wait 65 seconds from final manager processing, and repeat with a new opaque run ID. Do not remove the failed attempt from the evaluation denominator.
