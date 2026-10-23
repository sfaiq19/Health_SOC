# Archive setup and verification

These settings have been checked against Wazuh documentation, but have not been executed on the lab VM.

In the existing `<global>` section of `/var/ossec/etc/ossec.conf`, set `<logall_json>yes</logall_json>` and retain JSON alert output. In `/etc/filebeat/filebeat.yml`, enable `archives` inside the existing Wazuh module configuration. Restart Wazuh manager and Filebeat; inspect their status and logs for errors. Do not add a second conflicting global/module block.

Create `wazuh-archives-*` and `wazuh-alerts-*` data views. Confirm an actual benign `service_heartbeat` and `device_telemetry` event appear in archives before checking alerts. Record the index mappings; bytes and durations need numeric fields for summation. Retain seven days in live lab indexes while preserving finalized evidence bundles separately. Enable retention only after reviewing the exact policy supported by the installed indexer.

Count unique source `event_id` values against `data.event_id` in the archives for a bounded run; reconcile after up to 120 seconds. Observe source time `data.event_time` and manager `timestamp` separately. A populated local archives.json does not prove successful indexer forwarding.

Test one dummy file update after the initial FIM scan, record the installed native rule IDs and old/new digest fields, and restore before the measured run. No file diff content is required; SHA-256 and path are sufficient for these fictional documents.

References: https://documentation.wazuh.com/current/user-manual/manager/event-logging.html and https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html
