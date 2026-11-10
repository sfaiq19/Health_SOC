"""Synthetic unit artifacts, never native lab evidence; tshark remains an explicit test seam."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import struct
from uuid import uuid4

from hospital_soc.evidence_contract import make_intent


def evidence_bundle(root, scenario='baseline'):
    identity = '00000000-0000-0000-0000-000000000001'
    start = datetime(2026, 10, 22, tzinfo=timezone.utc)
    duration = 600 if scenario == 'baseline' else 75 if scenario == 's1' else 50
    def iso(seconds):
        return (start + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')
    options = dict(duration_s=600, pause_documents=False, include_exports=True) if scenario == 'baseline' else {}
    intent = make_intent(scenario, 101, **options)
    manifest = {'run_id': identity, 'scenario': scenario, 'seed': 101, 'status': 'generated', 'receipts': [],
                'policy_mode': 'observe', 'started_at': iso(0), 'ended_at': iso(duration), 'notes': [],
                'metadata': {'intent': intent, 'document_root': 'C:/Lab/hospital/documents'}}
    before = {f'D{i:03}': sha256(f'before-{i}'.encode()).hexdigest() for i in range(1, 51)}
    after = {f'D{i:03}': sha256(f'after-{i}'.encode()).hexdigest() for i in range(1, 51)}
    events, rows, logged_in = [], [], set()

    def record(op):
        request_id = str(uuid4())
        event = {'run_id': identity, 'event_id': str(uuid4()), 'request_id': request_id,
                 'service': 'hospital-lab', 'action': op['action'], 'outcome': 'denied' if op['status'] == 401 else 'success',
                 'actor_id': op['actor'], 'actor_key': op['actor'] + '|10.77.0.10', 'http_status': op['status'],
                 'event_time': iso(op['at'] + .01), **op['details']}
        result = {}
        if op['action'] == 'lab_order_created':
            result = {'order_id': str(uuid4())}
            event.update(result)
        elif op['action'] == 'lab_result_created':
            result = {'result_id': str(uuid4())}
            event.update(result)
        elif op['action'] == 'export_completed':
            result = {'transfer_id': str(uuid4()), 'bytes_sent': op['details']['bytes_sent'],
                      'payload_sha256': sha256(b'synthetic fixture payload').hexdigest()}
            event.update(result)
        if op['action'] == 'document_update':
            name = op['details']['document_id']
            result = {'document_id': name, 'sha256_before': before[name], 'sha256_after': after[name]}
            event.update(result)
        events.append(event)
        manifest['receipts'].append({'request_id': request_id, 'response_request_id': request_id,
            'method': op['method'], 'path': op['path'], 'actor': op['actor'], 'status': op['status'],
            'started_at': iso(op['at']), 'ended_at': iso(op['at'] + .05), 'result': result})
        rows.append({'frame.number': str(len(rows) + 1), 'frame.time_epoch': str((start + timedelta(seconds=op['at'])).timestamp()),
            'ip.src': '10.77.0.10', 'ip.dst': '10.77.0.1', 'http.request.method': op['method'],
            'http.request.uri': op['path'], 'http.request.line': f'X-Lab-Run-ID: {identity}'})
    for op in intent['operations']:
        actor = op['actor']
        if actor != 'anonymous' and not actor.startswith('device-') and op['action'] != 'login_failure' and actor not in logged_in:
            record(dict(method='POST', path='/api/auth/login', actor=actor, status=200,
                        action='login_success', at=op['at'], details={}))
            logged_in.add(actor)
        record(op)
    archives = [{'data': item, 'agent': {'name': 'hospital-win'},
                 'timestamp': (datetime.fromisoformat(item['event_time'].replace('Z', '+00:00')) + timedelta(seconds=1)).isoformat()} for item in events]
    alerts = []
    if scenario == 's2':
        last = next(event for event in reversed(events) if event['action'] == 'document_update')
        alerts.append({'data': last, 'rule': {'id': '110201'}, 'timestamp': iso(50)})
        for i, name in enumerate(before):
            alerts.append({'agent': {'name': 'hospital-win'}, 'timestamp': iso(i + 1),
                           'syscheck': {'path': f'C:/Lab/hospital/documents/{name}.txt',
                                        'sha256_before': before[name], 'sha256_after': after[name]}})
        (root / 'file-hashes-before.json').write_text(json.dumps(before))
        (root / 'file-hashes-after.json').write_text(json.dumps(after))
    for name, values in [('app.jsonl', events), ('archives.jsonl', archives), ('alerts.jsonl', alerts)]:
        (root / name).write_text(''.join(json.dumps(item) + '\n' for item in values))
    section = struct.pack('<IIIHHqI', 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
    interface = struct.pack('<IIHHII', 1, 20, 1, 0, 65535, 20)
    packet = struct.pack('<IIIIIII', 6, 36, 0, 0, 1, 1, 1) + b'\0\0\0\0' + struct.pack('<I', 36)
    (root / 'traffic.pcapng').write_bytes(section + interface + packet)
    import csv
    with (root / 'frames.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    (root / 'observations.json').write_text(json.dumps({'max_clock_offset_ms': 0,
        'max_index_visibility_delay_s': 1, 'capture_dropped_packets': 0,
        'collection_checked_at': iso(duration + 30), 'first_measured_run': True}))
    spec = importlib.util.spec_from_file_location('fixture_native_driver', 'scripts/verify-native-rules.py')
    driver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(driver)
    rules = Path('siem/healthcare_rules.xml').read_bytes()
    (root / 'healthcare_rules.xml').write_bytes(rules)
    cases = [{'case': 'loaded-revision', 'expected_rules': ['110001'], 'observed_rules': ['110001'], 'passed': True, 'revision_verified': True}]
    cases += [{'case': name, 'expected_rules': expected, 'observed_rules': expected, 'passed': True} for name, _, expected in driver.cases()]
    (root / 'native-rule-tests.json').write_text(json.dumps({'validation_schema': 2, 'engine': 'wazuh-logtest',
        'success': True, 'rules_sha256': sha256(rules).hexdigest(), 'cases': cases,
        'loaded_revision': driver.rule_revision(rules.decode()), 'version': 'synthetic fixture Wazuh 4.14.0',
        'rules_path': '/var/ossec/etc/rules/healthcare_rules.xml',
        'config_path': '/var/ossec/etc/ossec.conf', 'executable_path': '/var/ossec/bin/wazuh-logtest',
        'snapshot': {'/var/ossec/etc/rules/healthcare_rules.xml': sha256(rules).hexdigest(),
                     '/var/ossec/etc/ossec.conf': sha256(b'synthetic config').hexdigest(),
                     '/var/ossec/bin/wazuh-logtest': sha256(b'synthetic executable').hexdigest()}}))
    return manifest, rows
