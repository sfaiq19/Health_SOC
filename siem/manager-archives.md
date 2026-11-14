# Archive setup and verification

Archive forwarding, numeric mappings and native FIM were exercised on the November 13 Wazuh 4.14.10 lab. Every rebuilt installation still needs its own collection and mapping checks. Private evidence lives under `%USERPROFILE%\HealthcareSOCLab\evidence\measured-20261113`; it is not bundled in Git.

In the existing `<global>` section of `/var/ossec/etc/ossec.conf`, set `<logall_json>yes</logall_json>` and retain JSON alert output. In `/etc/filebeat/filebeat.yml`, enable `archives` inside the existing Wazuh module configuration. Restart Wazuh manager and Filebeat; inspect their status and logs for errors. Do not add a second conflicting global/module block.

Create `wazuh-archives-*` and `wazuh-alerts-*` data views with time field `timestamp`. Confirm an actual benign `service_heartbeat` and `device_telemetry` event appear in archives before checking alerts. Retain finalized evidence separately; the proposed seven-day live-index retention is not an implemented retention policy. Configure it only after checking the installed indexer's policy support.

## Numeric template before first hospital ingestion

The installed lab initially mapped these application fields as `keyword`. The export-byte panel needs numeric aggregation. Use the following explicit types in **both** the local Filebeat template and loaded indexer template:

| Field | Type |
|---|---|
| `data.bytes_sent` | `long` |
| `data.http_status` | `integer` |
| `data.duration_ms` | `long` |
| `data.service` and 26 hospital string/ID fields (`run_id`, `event_id`, `request_id`, `event_time`, `actor_id`, `actor_role`, `actor_key`, `outcome`, `patient_id`, `care_scope`, `document_id`, `destination_id`, `destination_approved`, `transfer_id`, `payload_sha256`, `sha256_before`, `sha256_after`, `source_ip`, `operation`, `order_id`, `result_id`, `path`, `device_id`, `destination_ip`, `destination_port`, `schema_version`) | `keyword` |

> **2026-11-14 daily-rollover collision & remediation:** Default `wazuh-template.json` leaves `data.service` unmapped. When `syscollector` ingests first into a new daily index after midnight UTC, dynamic mapping sets `data.service` to a multi-field object, causing OpenSearch HTTP `400 mapper_parsing_exception` rejections for every hospital event (`"service": "hospital-lab"`). This occurred during the first Nov 14 soak (`live-revalidation-20261114/01-soak-15m-replacement`, `0/760` indexed despite `760/760` in `archives.json`). Pin `data.service` and the 26 hospital string/ID fields as explicit `keyword` in `/etc/filebeat/wazuh-template.json` and `_template/wazuh` before ingestion; on Nov 14, backing up and migrating `wazuh-archives-4.x-2026.11.14` (`10,091/10,091` docs, `0` failures) + updating `wazuh-alerts-4.x-2026.11.14` and the template eliminated the conflict.

On a fresh installation, stop Filebeat before forwarding hospital events. Preserve the complete Wazuh template, including index patterns, settings and all other mappings. Merge the three entries into `mappings.properties.data.properties`; do not upload the small fragment below as a replacement template. Wazuh's [4.14.10 template](https://raw.githubusercontent.com/wazuh/wazuh/v4.14.10/extensions/elasticsearch/7.x/wazuh-template.json) covers `wazuh-alerts-4.x-*` and `wazuh-archives-4.x-*`.

Ubuntu Bash, after installing/configuring Filebeat and its private credentials/certificates:

```bash
sudo systemctl stop filebeat
sudo cp -p /etc/filebeat/wazuh-template.json /etc/filebeat/wazuh-template.json.before-hospital-numeric
sudo python3 - <<'PY'
import json
from pathlib import Path
path = Path('/etc/filebeat/wazuh-template.json')
template = json.loads(path.read_text())
assert {'wazuh-alerts-4.x-*', 'wazuh-archives-4.x-*'} <= set(template['index_patterns'])
fields = template['mappings']['properties']['data']['properties']
for field, kind in [('bytes_sent', 'long'), ('http_status', 'integer'), ('duration_ms', 'long')]:
    fields[field] = {'type': kind}
path.write_text(json.dumps(template, indent=2) + '\n')
PY
sudo filebeat test config
sudo filebeat test output
sudo filebeat setup --index-management \
  -E output.logstash.enabled=false \
  -E setup.template.json.enabled=true \
  -E setup.template.json.path=/etc/filebeat/wazuh-template.json \
  -E setup.template.json.name=wazuh \
  -E setup.template.overwrite=true
```

Run once against the intended isolated indexer using the configured Filebeat authentication. Do not put passwords into shell history. Inspect `GET /_template/wazuh` in authenticated Dashboard Dev Tools before starting Filebeat. Confirm the three explicit mappings and both index patterns; save the response privately. The [Wazuh Filebeat configuration](https://documentation.wazuh.com/current/user-manual/manager/indexer-integration.html) describes the JSON template settings, and the [upgrade procedure](https://documentation.wazuh.com/current/upgrade-guide/upgrading-central-components.html) documents loading index management with Filebeat.

Start Filebeat (`sudo systemctl start filebeat`), generate a bounded hospital smoke request, then inspect the actual indices as well as the template:

```text
GET /wazuh-archives-4.x-*,wazuh-alerts-4.x-*/_mapping/field/data.bytes_sent,data.http_status,data.duration_ms
GET /wazuh-archives-4.x-*,wazuh-alerts-4.x-*/_field_caps?fields=data.bytes_sent,data.http_status,data.duration_ms
```

Save these results with the smoke event/run ID and UTC interval. Verify the populated hospital indices show `long`, `integer`, `long`, aggregatable fields and no conflicting `keyword` type across the data view. Refresh the two data views' field lists. An updated template alone does not repair an already created index, even if hospital data has not yet arrived.

## Existing indices and historical repair

On November 13 the operator updated `/etc/filebeat/wazuh-template.json` and `_template/wazuh`, then reindexed all four existing alert/archive indices with corrected mappings. The saved `query-results/Q5_s3_all_runs.json` shows a numeric sum of `21,750,000` B; `reconciliation-summary.json` records `11/11` receiver matches. Values can remain strings in `_source` even when indexed numerically. This supports the export-byte aggregation; the three required types still need the mapping responses on a rebuild.

An existing field type cannot be changed in place. If mapping checks find a conflict, stop this fresh-install path and plan a separately reviewed migration: snapshot/export original indices, record names/counts/run IDs, pause ingestion at a documented boundary, create explicitly mapped destination indices, reindex, check failures/counts and independent event-ID/digest/byte reconciliation, then arrange data-view/alias cutover and resume forwarding. A wildcard that includes originals and copies will double-count. Keep originals until backup, validation and rollback are established. This guide intentionally supplies no automated deletion or replacement sequence. See the [OpenSearch mapping restriction](https://docs.opensearch.org/latest/api-reference/index-apis/put-mapping/) and [Wazuh reindex guidance](https://documentation.wazuh.com/current/user-manual/wazuh-indexer/re-indexing.html).

Count unique source `event_id` values against `data.event_id` in the archives for a bounded run; reconcile after up to 120 seconds. Observe source time `data.event_time` and manager `timestamp` separately. A populated local archives.json does not prove successful indexer forwarding.

Test one dummy file update after the initial FIM scan, record the installed native rule IDs and old/new digest fields, and restore before the measured run. No file diff content is required; SHA-256 and path are sufficient for these fictional documents.

References: https://documentation.wazuh.com/current/user-manual/manager/event-logging.html and https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/basic-settings.html
