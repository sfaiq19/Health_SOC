"""Reconcile observations with ground truth; absent channels never become clean results."""
from dataclasses import asdict, is_dataclass
from datetime import datetime, timedelta
from hashlib import sha256
import csv
import json
import ntpath
from pathlib import Path
import subprocess
from uuid import UUID

from .packets import validate_pcapng, verified_packet_rows

EXPECTED = {'s1': {'110101', '110102', '110103'}, 's2': {'110201'}, 's3': {'110302'}, 'baseline': set()}
ACTIONABLE = {'110101', '110102', '110103', '110201', '110301', '110302'}


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
                or not isinstance(manifest.get('notes', []), list)):
            raise ValueError('Invalid run interval or receipts')
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
                        for key in ['run_id', 'event_id', 'request_id', 'event_time']:
                            if key in data and not isinstance(data[key], str):
                                raise ValueError(f'{key} must be a string')
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
    observed = {str(event.get('rule', {}).get('id')) for event in alerts
                if event.get('data', {}).get('run_id') == run_id and str(event.get('rule', {}).get('id')) in ACTIONABLE}
    result['expected_rules'], result['observed_rules'] = sorted(EXPECTED[scenario]), sorted(observed)
    result['attack_detection_passed'] = (EXPECTED[scenario] <= observed) if scenario != 'baseline' else not observed
    if not result['attack_detection_passed']:
        issues.append('Expected detection families missing, or actionable baseline incidents observed')
    if not source:
        issues.append('No source events for this run')
    else:
        source_ids = {event.get('event_id') for event in source}
        archive_ids = [event.get('event_id') for event in archives]
        if None in source_ids or len(source_ids) != len(source):
            issues.append('Missing or duplicate source event IDs')
        result.update(source_events=len(source_ids), archived_source_events=len(source_ids & set(archive_ids)),
                      archive_duplicates=len(archive_ids) - len(set(archive_ids)),
                      collection_coverage=len(source_ids & set(archive_ids)) / len(source_ids))
        if result['collection_coverage'] != 1:
            issues.append('Source-to-archive coverage is incomplete')
        source_by_id = {event.get('event_id'): event for event in source}
        for event in raw_archives:
            data = event.get('data', {})
            original = source_by_id.get(data.get('event_id'))
            if original is None or data.get('run_id') != run_id:
                continue
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
        for event in alerts:
            if event.get('data', {}).get('run_id') == run_id and str(event.get('rule', {}).get('id')) in ACTIONABLE:
                try:
                    original = source_by_id.get(event['data'].get('event_id'))
                    if original is None or any(event['data'].get(key) != original.get(key) for key in ['action', 'outcome', 'actor_id', 'event_time']):
                        issues.append('Actionable alert does not reconcile with its source event')
                    latency = (instant(event['timestamp']) - instant(event['data']['event_time'])).total_seconds()
                    result['alert_latencies_s'].append(latency)
                    if not -1 <= latency <= 30:
                        issues.append('Alert latency outside target or clock uncertainty')
                except (KeyError, ValueError, TypeError):
                    issues.append('Alert latency unknown')

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
        if isinstance(before, dict) and isinstance(after, dict) and len(before) == 50 and set(before) == set(after):
            correlated = set()
            document_root = manifest.get('metadata', {}).get('document_root') if isinstance(manifest.get('metadata', {}), dict) else None
            if not isinstance(document_root, str) or not ntpath.isabs(document_root):
                issues.append('Canonical dummy document root is missing')
            for event in alerts:
                check = event.get('syscheck', {})
                if event.get('agent', {}).get('name') != 'hospital-win' or not check.get('path'):
                    continue
                identity = check['path'].replace('\\', '/').rsplit('/', 1)[-1].removesuffix('.txt')
                try:
                    in_window = start <= instant(event['timestamp']) <= end + timedelta(seconds=120)
                except (KeyError, ValueError, TypeError):
                    in_window = False
                same_root = isinstance(document_root, str) and ntpath.normcase(ntpath.normpath(ntpath.dirname(check['path']))) == ntpath.normcase(ntpath.normpath(document_root))
                if identity in before and same_root and in_window and before[identity] != after[identity] and check.get('sha256_before') == before[identity] and check.get('sha256_after') == after[identity]:
                    correlated.add(identity)
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
