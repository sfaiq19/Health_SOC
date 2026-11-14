"""Reconcile observations with ground truth; absent channels never become clean results."""
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import csv
import json
import ntpath
import re
from pathlib import Path
import subprocess
from uuid import UUID

from .packets import validate_pcapng, verified_packet_rows
from .evidence_contract import canonical_uuid as _raw_canonical_uuid, validate_receipts, reconcile_operations
from .native_validation import cases as native_cases, check_transcript, validate_expiry_transcript


def canonical_uuid(value):
    try:
        return _raw_canonical_uuid(value)
    except (ValueError, TypeError, AttributeError):
        return False

EXPECTED = {'s1': {'110101', '110102', '110103'}, 's2': {'110201'}, 's3': {'110302'}, 'baseline': set()}
ACTIONABLE = {
    '110101': {'action': 'login_failure', 'outcome': 'denied'},
    '110102': {'action': 'record_read', 'outcome': 'success', 'care_scope': 'unassigned'},
    '110103': {'action': 'record_read', 'outcome': 'success'},
    '110201': {'action': 'document_update', 'outcome': 'success'},
    '110301': {'action': 'export_completed', 'outcome': 'success', 'destination_approved': 'no'},
    '110302': {'action': 'export_completed', 'outcome': 'success', 'destination_approved': 'no'},
}


def eligible_alert(rule_id, source, data):
    """Check the trigger against the hospital rule family; Wazuh owns frequency state."""
    if source.get('service') != 'hospital-lab' or data.get('service') != 'hospital-lab':
        return False
    if any(source.get(key) != value or data.get(key) != value for key, value in ACTIONABLE[rule_id].items()):
        return False
    if rule_id in {'110101', '110103', '110201'}:
        actor_key = source.get('actor_key')
        return isinstance(actor_key, str) and bool(actor_key) and data.get('actor_key') == actor_key
    if rule_id in {'110301', '110302'}:
        size, decoded = source.get('bytes_sent'), data.get('bytes_sent')
        # Native Wazuh serializes numeric JSON fields as decimal strings.
        if type(size) is not int or size <= 0:
            return False
        if not ((type(decoded) is int and decoded == size) or decoded == str(size)):
            return False
        return (size >= 1_000_000) == (rule_id == '110302')
    return True


def instant(value):
    if not isinstance(value, str):
        raise ValueError('Timestamp must be a string')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamp has no timezone')
    return parsed


def evaluate_run(manifest, artifacts_dir: Path) -> dict:
    if is_dataclass(manifest):
        manifest = asdict(manifest)
    result = {'status': 'incomplete', 'missing_evidence': [], 'issues': [],
              'attack_detection_passed': False, 'collection_coverage': None,
              'source_events': None, 'archived_source_events': None, 'archive_duplicates': None,
              'expected_rules': [], 'observed_rules': [], 'alert_latencies_s': [],
              'fim_correlated_files': None, 'transfers_verified': None}
    issues = result['issues']
    try:
        run_id, scenario = manifest['run_id'], manifest['scenario']
        if str(UUID(run_id)) != run_id or scenario not in EXPECTED or manifest['status'] != 'generated':
            raise ValueError('Generator failed or identity/scenario invalid')
        start, end = instant(manifest['started_at']), instant(manifest['ended_at'])
        if (end < start or not isinstance(manifest['receipts'], list)
                or any(not isinstance(item, dict) for item in manifest['receipts'])
                or not isinstance(manifest.get('notes', []), list)
                or not isinstance(manifest.get('metadata', {}), dict)):
            raise ValueError('Invalid run interval or receipts')
        validate_receipts(manifest['receipts'])
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        result.update(status='invalid')
        issues.append(f'Invalid manifest: {error}')
        return result
    result['run_id'] = run_id
    if any('Diagnostic timing' in str(note) for note in manifest.get('notes', [])):
        issues.append('diagnostic_timing')
    if manifest.get('policy_mode') != 'observe':
        issues.append('Policy enforcement run requires separate mitigation review; not an observe-mode detection trial')

    required = ['app.jsonl', 'archives.jsonl', 'alerts.jsonl', 'traffic.pcapng', 'frames.csv',
                'observations.json', 'native-rule-tests.json', 'healthcare_rules.xml']
    if scenario == 's2':
        required += ['file-hashes-before.json', 'file-hashes-after.json']
    if scenario == 's3':
        required += ['receiver.jsonl']
    result['missing_evidence'] = [name for name in required if not (artifacts_dir / name).is_file()]

    def load(name, lines=False):
        path = artifacts_dir / name
        if not path.is_file():
            return [] if lines else None
        try:
            content = path.read_text(encoding='utf-8-sig')
            value = [json.loads(line) for line in content.splitlines() if line.strip()] if lines else json.loads(content)
            if lines and any(not isinstance(item, dict) for item in value):
                raise ValueError('Expected JSON objects')
            if lines:
                for item in value:
                    for key in ['data', 'rule', 'syscheck', 'agent']:
                        if key in item and not isinstance(item[key], dict):
                            raise ValueError(f'{key} must be an object')
                    for key in ['path', 'sha256_before', 'sha256_after']:
                        if key in item.get('syscheck', {}) and not isinstance(item['syscheck'][key], str):
                            raise ValueError(f'syscheck.{key} must be a string')
                    for data in [item, item.get('data', {})]:
                        for key in ['run_id', 'event_id', 'request_id', 'event_time', 'document_id']:
                            if key in data and not isinstance(data[key], str):
                                raise ValueError(f'{key} must be a string')
                        if name != 'alerts.jsonl' and data.get('service') == 'hospital-lab':
                            if not canonical_uuid(data.get('event_id')) or not canonical_uuid(data.get('request_id')):
                                raise ValueError('Hospital event identity missing or invalid')
            return value
        except (ValueError, OSError) as error:
            issues.append(f'Invalid {name}: {error}')
            result['status'] = 'invalid'
            return [] if lines else None

    source = [event for event in load('app.jsonl', True) if event.get('run_id') == run_id]
    raw_archives = load('archives.jsonl', True)
    archives = [event.get('data', {}) for event in raw_archives
                if event.get('data', {}).get('run_id') == run_id]
    alerts = load('alerts.jsonl', True)
    source_by_id = {event.get('event_id'): event for event in source if canonical_uuid(event.get('event_id'))}
    observed = set()
    for event in alerts:
        data = event.get('data') if isinstance(event.get('data'), dict) else {}
        rule = event.get('rule') if isinstance(event.get('rule'), dict) else {}
        rule_id = str(rule.get('id'))
        if data.get('run_id') == run_id and rule_id in ACTIONABLE:
            original = source_by_id.get(data.get('event_id'))
            valid = (
                isinstance(event.get('agent'), dict)
                and event['agent'].get('name') == 'hospital-win'
                and canonical_uuid(data.get('event_id'))
                and canonical_uuid(data.get('request_id'))
                and original is not None
                and eligible_alert(rule_id, original, data)
                and all(data.get(key) == original.get(key) for key in ['run_id', 'event_id', 'request_id', 'action', 'outcome', 'actor_id', 'event_time'])
            )
            if not valid:
                issues.append('Actionable alert does not reconcile with its source event')
                continue
            try:
                latency = (instant(event['timestamp']) - instant(data['event_time'])).total_seconds()
                observed.add(rule_id)
                result['alert_latencies_s'].append(latency)
                if not -1 <= latency <= 30:
                    issues.append('Alert latency outside target or clock uncertainty')
            except (KeyError, ValueError, TypeError):
                issues.append('Alert latency unknown')

    result['expected_rules'], result['observed_rules'] = sorted(EXPECTED[scenario]), sorted(observed)
    result['attack_detection_passed'] = (EXPECTED[scenario] <= observed) if scenario != 'baseline' else not observed
    if not result['attack_detection_passed']:
        issues.append('Expected detection families missing, or actionable baseline incidents observed')
    if not source:
        issues.append('No source events for this run')
    else:
        for event in source:
            try:
                if not start - timedelta(seconds=1) <= instant(event['event_time']) <= end + timedelta(seconds=1):
                    issues.append('Source event lies outside the run interval')
            except (ValueError, KeyError):
                issues.append('Source event timestamp is missing or invalid')
        try:
            issues.extend(reconcile_operations(manifest, source, start, end))
        except (ValueError, KeyError, TypeError, AttributeError):
            result['status'] = 'invalid'
            issues.append('Malformed operation evidence prevents reconciliation')
        source_ids = {event.get('event_id') for event in source}
        archive_ids = [event.get('event_id') for event in archives]
        if None in source_ids or len(source_ids) != len(source):
            issues.append('Missing or duplicate source event IDs')
        result.update(source_events=len(source_ids), archived_source_events=len(source_ids & set(archive_ids)),
                      archive_duplicates=len(archive_ids) - len(set(archive_ids)),
                      collection_coverage=len(source_ids & set(archive_ids)) / len(source_ids))
        if result['collection_coverage'] != 1:
            issues.append('Source-to-archive coverage is incomplete')
        for event in raw_archives:
            data = event.get('data', {})
            original = source_by_id.get(data.get('event_id'))
            if original is None or data.get('run_id') != run_id:
                continue
            if event.get('agent', {}).get('name') != 'hospital-win':
                issues.append('Archived source event endpoint is missing or inconsistent')
            try:
                source_at, arrived = instant(original['event_time']), instant(event['timestamp'])
                if not -1 <= (arrived - source_at).total_seconds() <= 120 or arrived > end + timedelta(seconds=120):
                    issues.append('Archive collection is delayed or contradicts the run deadline')
                for key in ['run_id', 'request_id', 'action', 'outcome', 'actor_id', 'event_time']:
                    if key in original and original[key] != data.get(key):
                        issues.append('Archive identity/action disagrees with source evidence')
            except (KeyError, ValueError):
                issues.append('Archive processing timestamp is missing or invalid')
        request_ids = {event.get('request_id') for event in source}
        if not manifest['receipts'] or any(receipt.get('request_id') not in request_ids for receipt in manifest['receipts']):
            issues.append('Generator receipts do not reconcile with source requests')

    observations = load('observations.json')
    if not isinstance(observations, dict):
        issues.append('Clock, index visibility and capture health observations missing')
    else:
        clock = observations.get('max_clock_offset_ms')
        delay = observations.get('max_index_visibility_delay_s')
        drops = observations.get('capture_dropped_packets')
        if type(clock) not in (int, float) or not 0 <= clock <= 1000:
            issues.append('Clock offset unknown or excessive')
        if type(delay) not in (int, float) or not 0 <= delay <= 60:
            issues.append('Index visibility delay unknown or excessive')
        if type(drops) is not int or drops != 0:
            issues.append('Capture loss unknown or nonzero')
        try:
            checked = instant(observations['collection_checked_at'])
            processed = [instant(event['timestamp']) for event in raw_archives if event.get('data', {}).get('run_id') == run_id]
            if checked < end or checked > end + timedelta(seconds=120) or any(value > checked for value in processed):
                issues.append('Collection check time contradicts archive arrival or deadline')
        except (KeyError, ValueError):
            issues.append('Collection observation time missing or invalid')
        if observations.get('first_measured_run') is not True:
            try:
                prior = instant(observations['prior_run_final_manager_at'])
                quiet = instant(observations['quiet_interval_started_at'])
                previous_id = observations['previous_measured_run_id']
                if str(UUID(previous_id)) != previous_id or previous_id == run_id:
                    raise ValueError('Invalid preceding run ID')
                if prior > quiet or (start - quiet).total_seconds() < 65:
                    issues.append('Prior-run ingestion drain and 65-second quiet interval not satisfied')
                if any(event.get('data', {}).get('run_id') == previous_id and instant(event.get('timestamp')) > prior for event in raw_archives):
                    issues.append('Late preceding-run events invalidate the recorded collection drain')
            except (KeyError, ValueError, TypeError, AttributeError):
                issues.append('Preceding-run collection/quiet-interval evidence missing or invalid')
    proof = load('native-rule-tests.json')
    rule_path = artifacts_dir / 'healthcare_rules.xml'
    if not isinstance(proof, dict) or proof.get('engine') != 'wazuh-logtest' or proof.get('success') is not True:
        issues.append('Native Wazuh rule validation is missing or failed')
    elif not rule_path.is_file() or proof.get('rules_sha256') != sha256(rule_path.read_bytes()).hexdigest():
        issues.append('Native validation does not match the collected rules file')
    else:
        cases = proof.get('cases')
        expectations = {'loaded-revision': ['110001'], **{name: expected for name, _, expected in native_cases()}}
        case_names = set(expectations)
        valid_cases = (isinstance(cases, list) and len(cases) == len(case_names)
                       and all(isinstance(item, dict) and isinstance(item.get('case'), str) for item in cases))
        if valid_cases:
            valid_cases = ({item['case'] for item in cases} == case_names and all(
                item.get('passed') is True and item.get('expected_rules') == expectations[item['case']]
                and item.get('observed_rules') == expectations[item['case']] for item in cases))
        if proof.get('validation_schema') != 3 or not valid_cases:
            issues.append('Native proof lacks complete per-event case results')
        else:
            expiry_sessions = [case.get('session_sha256') for case in cases if case['case'].endswith('-expiry')]
            if (any(not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) for value in expiry_sessions)
                    or len(set(value for value in expiry_sessions if isinstance(value, str))) != 3):
                issues.append('Native expiry cases lack independent sessions')
            for case in cases:
                name = case['case']  # already checked against the authoritative allowlist
                try:
                    raw = (artifacts_dir / f'{name}.txt').read_bytes()
                    output = raw.decode('utf-8')
                except (OSError, UnicodeError):
                    issues.append(f'Native transcript missing or unreadable: {name}')
                    continue
                challenge = proof.get('loaded_revision') if name == 'loaded-revision' else None
                if (sha256(raw).hexdigest() != case.get('transcript_sha256')
                        or not check_transcript(output, expectations[name], challenge)['passed']
                        or (name.endswith('-expiry') and not validate_expiry_transcript(name, output, case))):
                    issues.append(f'Native transcript disagrees with the evidence contract: {name}')
        revision = proof.get('loaded_revision')
        rules_text = rule_path.read_text(encoding='utf-8').replace('\r\n', '\n')
        markers = re.findall(r'\[hc-rev:([0-9a-f]{64})\]', rules_text)
        normalized = re.sub(r'\[hc-rev:[0-9a-f]{64}\]', '[hc-rev:' + '0' * 64 + ']', rules_text)
        if not markers or len(markers) != 1 or revision != markers[0] or sha256(normalized.encode()).hexdigest() != revision:
            issues.append('Native proof revision is not bound to the rules content')
        if not valid_cases or not any(item.get('case') == 'loaded-revision' and item.get('revision_verified') is True for item in cases):
            issues.append('Native proof has no successful loaded-revision challenge')
        snapshot = proof.get('snapshot')
        paths = [proof.get(key) for key in ['rules_path', 'config_path', 'executable_path']]
        valid_snapshot = (isinstance(snapshot, dict) and len(snapshot) == 3
                          and all(isinstance(path, str) and (ntpath.isabs(path) or path.startswith('/')) for path in paths)
                          and set(snapshot) == set(paths)
                          and all(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest) for digest in snapshot.values())
                          and snapshot.get(paths[0]) == proof.get('rules_sha256'))
        if not valid_snapshot or not isinstance(proof.get('version'), str) or not re.search(r'\bv?4\.14\.\d+\b', proof['version']):
            issues.append('Native proof lacks engine/configuration provenance')

    capture = artifacts_dir / 'traffic.pcapng'
    capture_valid = False
    if capture.is_file():
        try:
            result['captured_packets'] = validate_pcapng(capture)
            capture_valid = True
        except (ValueError, OSError) as error:
            issues.append(f'Invalid PCAPNG capture: {error}')
    frames = artifacts_dir / 'frames.csv'
    if frames.is_file() and capture_valid:
        try:
            rows = verified_packet_rows(capture, frames)
            if not rows or not {'frame.number', 'frame.time_epoch', 'ip.src', 'ip.dst', 'http.request.method', 'http.request.uri', 'http.request.line'} <= set(rows[0]):
                issues.append('Packet field export is absent or malformed')
            else:
                host = '10.77.0.1'
                peer = '10.77.0.10'
                flows = [row for row in rows if {row['ip.src'], row['ip.dst']} == {host, peer}
                         and run_id in row['http.request.line']
                         and start.timestamp() - 1 <= float(row['frame.time_epoch']) <= end.timestamp() + 1]
                if not flows:
                    issues.append('No cross-host lab flow in packet field export')
                required_count = 30 if scenario == 's1' else 50 if scenario == 's2' else 1
                method, fragment = ('GET', '/api/records/') if scenario == 's1' else ('PUT', '/api/documents/') if scenario == 's2' else ('POST', '/receive')
                if scenario != 'baseline' and sum(row['http.request.method'] == method and fragment in row['http.request.uri'] for row in flows) < required_count:
                    issues.append('Scenario HTTP packet evidence is incomplete')
        except (ValueError, OSError, csv.Error, subprocess.TimeoutExpired) as error:
            issues.append(f'Packet field export not independently verified: {error}')

    if scenario == 's2':
        before, after = load('file-hashes-before.json'), load('file-hashes-after.json')
        expected_docs = {f'D{i:03}' for i in range(1, 51)}
        valid_inventories = (
            isinstance(before, dict) and isinstance(after, dict)
            and set(before) == expected_docs and set(after) == expected_docs
            and all(isinstance(v, str) and bool(re.fullmatch(r'[0-9a-f]{64}', v)) for v in before.values())
            and all(isinstance(v, str) and bool(re.fullmatch(r'[0-9a-f]{64}', v)) for v in after.values())
        )
        if valid_inventories:
            correlated = set()
            document_root = manifest.get('metadata', {}).get('document_root') if isinstance(manifest.get('metadata', {}), dict) else None
            if not isinstance(document_root, str) or not ntpath.isabs(document_root):
                issues.append('Canonical dummy document root is missing')

            fim_events_by_doc = {}
            names_on_windows = {ntpath.normcase(f'{doc}.txt'): doc for doc in expected_docs}
            for event in alerts:
                if not isinstance(event, dict):
                    continue
                check = event.get('syscheck')
                if not isinstance(check, dict) or not check.get('path'):
                    continue
                if event.get('agent', {}).get('name') != 'hospital-win':
                    continue
                try:
                    in_window = start <= instant(event['timestamp']) <= end + timedelta(seconds=120)
                except (KeyError, ValueError, TypeError):
                    in_window = False
                if not in_window:
                    continue
                path = check['path']
                same_root = (isinstance(document_root, str)
                             and ntpath.normcase(ntpath.normpath(ntpath.dirname(path))) == ntpath.normcase(ntpath.normpath(document_root)))
                if not same_root:
                    continue
                doc = names_on_windows.get(ntpath.normcase(ntpath.basename(path)))
                if doc is None:
                    issues.append('Contradictory or duplicate FIM observations detected')
                    continue
                fim_events_by_doc.setdefault(doc, []).append(check)

            manifest_receipts = manifest.get('receipts', []) if isinstance(manifest.get('receipts'), list) else []
            for r in manifest_receipts:
                if isinstance(r, dict) and r.get('method') == 'PUT':
                    res = r.get('result')
                    d_id = res.get('document_id') if isinstance(res, dict) else None
                    p_id = r.get('path', '').removeprefix('/api/documents/')
                    if (d_id and d_id not in expected_docs) or (p_id and p_id not in expected_docs and r.get('path', '').startswith('/api/documents/')):
                        issues.append('Missing or duplicate application document updates')

            for e in source:
                if isinstance(e, dict) and e.get('action') == 'document_update':
                    if e.get('document_id') not in expected_docs:
                        issues.append('Missing or duplicate application document updates')

            for doc_id in sorted(expected_docs):
                put_receipts = [
                    r for r in manifest_receipts
                    if isinstance(r, dict) and r.get('method') == 'PUT'
                    and (
                        r.get('path') == f'/api/documents/{doc_id}'
                        or (isinstance(r.get('result'), dict) and r['result'].get('document_id') == doc_id)
                    )
                ]
                req_ids = {r.get('request_id') for r in put_receipts if r.get('request_id')}
                doc_sources = [
                    e for e in source
                    if isinstance(e, dict) and e.get('action') == 'document_update'
                    and (e.get('document_id') == doc_id or e.get('request_id') in req_ids)
                ]
                if len(put_receipts) != 1 or len(doc_sources) != 1:
                    issues.append('Missing or duplicate application document updates')
                    continue

                receipt = put_receipts[0]
                source_event = doc_sources[0]
                receipt_result = receipt.get('result')
                valid_app_update = (
                    receipt.get('status') == 200
                    and isinstance(receipt_result, dict)
                    and receipt_result.get('document_id') == doc_id
                    and source_event.get('request_id') == receipt.get('request_id')
                    and source_event.get('action') == 'document_update'
                    and source_event.get('outcome') == 'success'
                    and source_event.get('http_status') == 200
                    and source_event.get('document_id') == doc_id
                )
                if not valid_app_update:
                    issues.append('Missing or duplicate application document updates')
                    continue

                app_before = receipt_result.get('sha256_before')
                app_after = receipt_result.get('sha256_after')
                src_before = source_event.get('sha256_before')
                src_after = source_event.get('sha256_after')
                inv_before = before[doc_id]
                inv_after = after[doc_id]

                if (inv_before == inv_after
                        or app_before != inv_before or app_after != inv_after
                        or src_before != inv_before or src_after != inv_after):
                    issues.append('Application document update digests disagree with inventory or FIM evidence')
                    continue

                fims = fim_events_by_doc.get(doc_id, [])
                if not fims:
                    continue
                if len(fims) > 1 or any(f.get('sha256_before') != inv_before or f.get('sha256_after') != inv_after for f in fims):
                    issues.append('Contradictory or duplicate FIM observations detected')
                    continue

                correlated.add(doc_id)

            result['fim_correlated_files'] = len(correlated)
            if len(correlated) != 50:
                issues.append('FIM digest corroboration incomplete; manual path/time fallback is not auto-accepted')
        else:
            issues.append('Document hash sets incomplete')
    if scenario == 's3':
        receipts = load('receiver.jsonl', True)
        transfers = [event for event in source if event.get('action') == 'export_completed']
        verified = 0
        for event in transfers:
            identity = event.get('transfer_id')
            try:
                if str(UUID(identity)) != identity:
                    raise ValueError()
            except (ValueError, TypeError, AttributeError):
                issues.append('Invalid transfer identity')
                continue
            body = artifacts_dir / 'received' / f'{identity}.bin'
            if body.is_file():
                digest = sha256(body.read_bytes()).hexdigest()
                if event.get('bytes_sent') == body.stat().st_size == 5000000 and event.get('payload_sha256') == digest and any(
                    item.get('transfer_id') == identity and item.get('sha256') == digest and item.get('received_bytes') == body.stat().st_size for item in receipts):
                    verified += 1
        result['transfers_verified'] = verified
        if not transfers or verified != len(transfers):
            issues.append('Independent received export objects/receipts incomplete')
    result['issues'] = sorted(set(issues))
    if not result['missing_evidence'] and not result['issues']:
        result['status'] = 'complete'
    return result
