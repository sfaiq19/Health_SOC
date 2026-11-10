"""Ground-truth intent and observed request contracts, outside monitored events."""
from collections import Counter
from datetime import datetime, timedelta
import re
from uuid import UUID


def canonical_uuid(value):
    return isinstance(value, str) and bool(value) and str(UUID(value)) == value


def time_value(value):
    if not isinstance(value, str):
        raise ValueError('Timestamp must be a string')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return parsed


def operation(method, path, actor, status, action, at=0, **details):
    return dict(method=method, path=path, actor=actor, status=status, action=action, at=at, details=details)


def primary_operations(scenario, seed, policy_mode='observe', **options):
    if scenario == 'baseline':
        from .workload import planned_operations
        planned = planned_operations(options['duration_s'], seed, options['pause_documents'], options['include_exports'])
        result = []
        for item in planned:
            at, kind = item['at'], item['kind']
            if kind == 'health':
                result.append(operation('GET', '/health', 'anonymous', 200, 'service_heartbeat', at))
            elif kind == 'devices':
                result.append(operation('POST', f"/api/devices/{item['device']}/telemetry", item['device'], 201, 'device_telemetry', at, device_id=item['device']))
            elif kind == 'documents':
                result.append(operation('PUT', f"/api/documents/{item['document']}", 'document-editor', 200, 'document_update', at, document_id=item['document']))
            elif kind == 'records':
                result.append(operation('GET', f"/api/records/{item['patient']}", 'nurse', 200, 'record_read', at, patient_id=item['patient'], care_scope='assigned'))
            elif kind == 'laboratory':
                result += [operation('POST', '/api/lab/orders', 'clinician', 201, 'lab_order_created', at, patient_id='P0001'),
                           operation('POST', '/api/lab/results', 'lab-service', 201, 'lab_result_created', at)]
            elif kind == 'login_typo':
                result.append(operation('POST', '/api/auth/login', 'nurse', 401, 'login_failure', at))
            elif kind == 'export':
                result.append(operation('POST', '/api/exports', 'records-clerk', 200, 'export_completed', at, destination_id='approved-lab', destination_approved='yes', bytes_sent=250000))
        return result
    result = [operation('GET', '/health', 'anonymous', 200, 'service_heartbeat')]
    if scenario == 's1':
        result += [operation('POST', '/api/auth/login', 'clinician', 401, 'login_failure', i * 5) for i in range(6)]
        result += [operation('GET', f'/api/records/P{i:04}', 'clinician', 200 if policy_mode == 'observe' else 403,
                             'record_read' if policy_mode == 'observe' else 'record_denied', 30 + (i - 100) * 1.5,
                             patient_id=f'P{i:04}', care_scope='unassigned') for i in range(100, 130)]
    elif scenario == 's2':
        result += [operation('GET', '/api/documents/hashes', 'document-editor', 200, 'document_inventory')]
        result += [operation('PUT', f'/api/documents/D{i:03}', 'document-editor', 200, 'document_update', i - 1, document_id=f'D{i:03}') for i in range(1, 51)]
        result += [operation('GET', '/api/documents/hashes', 'document-editor', 200, 'document_inventory', 50)]
    elif scenario == 's3':
        details = {'destination_id': 'unapproved-lab', 'destination_approved': 'no'}
        if policy_mode == 'observe':
            details['bytes_sent'] = 5000000
        result += [operation('POST', '/api/exports', 'records-clerk', 200 if policy_mode == 'observe' else 403,
                             'export_completed' if policy_mode == 'observe' else 'export_denied', **details)]
    else:
        raise ValueError('Unknown scenario')
    return result


def make_intent(scenario, seed, policy_mode='observe', diagnostic=False, **options):
    return {'schema_version': 1, 'timing': 'diagnostic' if diagnostic else 'measured', **options,
            'operations': primary_operations(scenario, seed, policy_mode, **options)}


def validate_receipts(receipts):
    ids = set()
    for receipt in receipts:
        if (not canonical_uuid(receipt.get('request_id')) or not canonical_uuid(receipt.get('response_request_id'))
                or receipt['request_id'] != receipt['response_request_id'] or receipt['request_id'] in ids
                or receipt.get('method') not in {'GET', 'POST', 'PUT'}
                or not isinstance(receipt.get('path'), str) or not isinstance(receipt.get('actor'), str)
                or type(receipt.get('status')) is not int or not 100 <= receipt['status'] <= 599
                or not isinstance(receipt.get('result'), dict)):
            raise ValueError('Malformed, duplicate or inconsistent request receipt')
        if time_value(receipt['ended_at']) < time_value(receipt['started_at']):
            raise ValueError('Receipt ends before it starts')
        for field, value in receipt['result'].items():
            if field in {'order_id', 'result_id', 'transfer_id'} and not canonical_uuid(value):
                raise ValueError('Response result identifier must be a canonical UUID')
            if field in {'sha256_before', 'sha256_after', 'payload_sha256'} and (not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)):
                raise ValueError('Response result digest must be SHA-256')
            if field == 'bytes_sent' and (type(value) is not int or not 1 <= value <= 10000000):
                raise ValueError('Response byte count must be a bounded integer')
            if field == 'document_id' and (not isinstance(value, str) or not re.fullmatch(r'D\d{3}', value) or not 1 <= int(value[1:]) <= 50):
                raise ValueError('Response document ID is invalid')
        ids.add(receipt['request_id'])


def reconcile_operations(manifest, source, start, end):
    issues = []
    intent = manifest.get('metadata', {}).get('intent')
    if not isinstance(intent, dict) or intent.get('schema_version') != 1:
        return ['Workload intent is missing or unsupported']
    if intent.get('timing') != 'measured':
        issues.append('Workload is not a measured acceptance run')
    try:
        options = {}
        if manifest['scenario'] == 'baseline':
            options = {key: intent[key] for key in ['duration_s', 'pause_documents', 'include_exports']}
            if type(options['duration_s']) is not int or any(type(options[key]) is not bool for key in ['pause_documents', 'include_exports']):
                raise ValueError('Invalid baseline options')
            if options['duration_s'] < 600 or options['pause_documents'] or not options['include_exports']:
                issues.append('Baseline lacks the full holdout duration or hospital workflow coverage')
            if (end - start).total_seconds() + 1 < options['duration_s']:
                issues.append('Baseline ended before its planned duration')
        expected = primary_operations(manifest['scenario'], manifest['seed'], manifest['policy_mode'], **options)
        if intent.get('operations') != expected:
            issues.append('Stored workload intent disagrees with the scenario plan')
    except (KeyError, ValueError, TypeError):
        return issues + ['Workload intent options are malformed']
    by_request = {}
    for event in source:
        if event.get('action') != 'operation_intent':
            by_request.setdefault(event.get('request_id'), []).append(event)
    observed, details_by_key = [], {}
    successful_logins = []
    for receipt in manifest['receipts']:
        began, finished = time_value(receipt['started_at']), time_value(receipt['ended_at'])
        if began < start - timedelta(seconds=1) or finished > end + timedelta(seconds=1):
            issues.append('Receipt lies outside the run interval')
        events = by_request.pop(receipt['request_id'], [])
        if len(events) != 1:
            issues.append('Each receipt must join exactly one terminal source event')
            continue
        event = events[0]
        key = (receipt['method'], receipt['path'], receipt['actor'], receipt['status'], event.get('action'))
        if event.get('http_status') != receipt['status'] or event.get('actor_id') != receipt['actor']:
            issues.append('Receipt status or actor disagrees with the source event')
        wanted_outcome = 'denied' if receipt['status'] in {401, 403} else 'success'
        if event.get('outcome') != wanted_outcome or receipt['status'] not in {200, 201, 401, 403}:
            issues.append('Required operation failed or has an inconsistent outcome')
        event_at = time_value(event['event_time'])
        if not began - timedelta(seconds=1) <= event_at <= finished + timedelta(seconds=1):
            issues.append('Source event time disagrees with its receipt interval')
        required_results = {'document_update': {'document_id', 'sha256_before', 'sha256_after'},
                            'lab_order_created': {'order_id'}, 'lab_result_created': {'result_id'},
                            'export_completed': {'transfer_id', 'bytes_sent', 'payload_sha256'}}
        if not required_results.get(event.get('action'), set()) <= set(receipt['result']):
            issues.append('Required response result fields are missing')
        for field, value in receipt['result'].items():
            if field in {'order_id', 'result_id', 'document_id', 'sha256_before', 'sha256_after', 'bytes_sent', 'payload_sha256', 'transfer_id'} and event.get(field) != value:
                issues.append('Receipt result disagrees with source evidence')
        if key[:2] == ('POST', '/api/auth/login') and receipt['status'] == 200 and event.get('action') == 'login_success':
            successful_logins.append(receipt['actor'])
        else:
            observed.append(key)
            details_by_key.setdefault(key, []).append(event)
    if by_request:
        issues.append('Terminal source events have no generator receipts')
    expected_keys = [(op['method'], op['path'], op['actor'], op['status'], op['action']) for op in expected]
    if Counter(observed) != Counter(expected_keys):
        issues.append('Observed operation counts or distinct targets disagree with workload intent')
    expected_humans = {op['actor'] for op in expected if op['actor'] not in {'anonymous'} and not op['actor'].startswith('device-') and op['action'] != 'login_failure'}
    if Counter(successful_logins) != Counter({actor: 1 for actor in expected_humans}):
        issues.append('Required authenticated session receipts are incomplete')
    for op, key in zip(expected, expected_keys):
        events = details_by_key.get(key, [])
        if events:
            event = events.pop(0)
            if time_value(event['event_time']) < start + timedelta(seconds=op['at'] - 1):
                issues.append('Observed operation precedes its planned schedule')
            if any(event.get(field) != value for field, value in op['details'].items()):
                issues.append('Observed object, care scope or transfer details disagree with intent')
    if manifest['scenario'] in {'s1', 's2'} and (end - start).total_seconds() + 1 < (75 if manifest['scenario'] == 's1' else 50):
        issues.append('Scenario timing is shorter than the planned measured sequence')
    return issues
