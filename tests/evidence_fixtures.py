"""Synthetic unit-test artifacts only. These are never live lab evidence."""
from hashlib import sha256
import json
import struct


def evidence_bundle(root, scenario='baseline'):
    identity = '00000000-0000-0000-0000-000000000001'
    action = 'document_update' if scenario == 's2' else 'service_heartbeat'
    count = 50 if scenario == 's2' else 1
    events = [{'run_id': identity, 'event_id': f'event-{i}', 'request_id': f'request-{i}',
               'service': 'hospital-lab', 'action': action, 'outcome': 'success',
               'actor_id': 'unit', 'actor_key': 'unit|10.77.0.10',
               'event_time': '2026-10-22T00:00:01Z'} for i in range(count)]
    archives = [{'data': item, 'timestamp': '2026-10-22T00:00:02Z'} for item in events]
    manifest = {'run_id': identity, 'scenario': scenario, 'status': 'generated',
                'receipts': [{'request_id': item['request_id'], 'status': 200} for item in events],
                'policy_mode': 'observe', 'started_at': '2026-10-22T00:00:00Z',
                'ended_at': '2026-10-22T00:01:00Z', 'notes': [],
                'metadata': {'document_root': 'C:/Lab/hospital/documents'}}
    alerts = []
    if scenario == 's2':
        alerts.append({'data': events[-1], 'rule': {'id': '110201'}, 'timestamp': '2026-10-22T00:00:02Z'})
        before = {f'D{i:03}': sha256(f'before-{i}'.encode()).hexdigest() for i in range(1, 51)}
        after = {f'D{i:03}': sha256(f'after-{i}'.encode()).hexdigest() for i in range(1, 51)}
        for name in before:
            alerts.append({'agent': {'name': 'hospital-win'}, 'timestamp': '2026-10-22T00:00:02Z',
                           'syscheck': {'path': f'C:/Lab/hospital/documents/{name}.txt',
                                        'sha256_before': before[name], 'sha256_after': after[name]}})
        (root / 'file-hashes-before.json').write_text(json.dumps(before))
        (root / 'file-hashes-after.json').write_text(json.dumps(after))
    for name, values in [('app.jsonl', events), ('archives.jsonl', archives), ('alerts.jsonl', alerts)]:
        (root / name).write_text(''.join(json.dumps(item) + '\n' for item in values))
    # Valid structural packet blocks. Unit tests replace the external tshark CSV verifier explicitly.
    section = struct.pack('<IIIHHqI', 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
    interface = struct.pack('<IIHHII', 1, 20, 1, 0, 65535, 20)
    packet = struct.pack('<IIIIIII', 6, 36, 0, 0, 1, 1, 1) + b'\0\0\0\0' + struct.pack('<I', 36)
    (root / 'traffic.pcapng').write_bytes(section + interface + packet)
    method, uri = ('PUT', '/api/documents/D001') if scenario == 's2' else ('GET', '/health')
    rows = [{'frame.number': str(i + 1), 'frame.time_epoch': '1792627201', 'ip.src': '10.77.0.10',
             'ip.dst': '10.77.0.1', 'http.request.method': method, 'http.request.uri': uri,
             'http.request.line': f'X-Lab-Run-ID: {identity}'} for i in range(count)]
    import csv
    with (root / 'frames.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (root / 'observations.json').write_text(json.dumps({'max_clock_offset_ms': 0,
        'max_index_visibility_delay_s': 1, 'capture_dropped_packets': 0,
        'collection_checked_at': '2026-10-22T00:01:30Z', 'first_measured_run': True}))
    rules = b'<group name="unit-fixture"/>'
    (root / 'healthcare_rules.xml').write_bytes(rules)
    (root / 'native-rule-tests.json').write_text(json.dumps({'engine': 'wazuh-logtest',
        'success': True, 'rules_sha256': sha256(rules).hexdigest()}))
    return manifest, rows
