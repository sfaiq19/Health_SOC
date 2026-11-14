"""Shared native expectations, transcript checks and revision provenance."""
from hashlib import sha256
from datetime import datetime
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from uuid import UUID, uuid4

REVISION = re.compile(r'\[hc-rev:([0-9a-f]{64})\]')
LOG_PREFIX = r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} wazuh_logtest'
INFO_PREFIX = re.compile(r'(?m)^' + LOG_PREFIX + r'\[INFO\] ')
REPLY_LINE = re.compile(r'(?m)^' + LOG_PREFIX + r'\[DEBUG\] Reply: (.+)$')
PHASE_ONE = re.compile(r'(?m)^\*\*Phase 1: Completed pre-decoding\.\s*$')
EXPIRY_CASES = {'auth-expiry': ('login_failure', 'denied', '110001', 5),
                'reads-expiry': ('record_read', 'success', '110002', 20),
                'writes-expiry': ('document_update', 'success', '110003', 20)}


def stamp_revision(text):
    text = text.replace('\r\n', '\n')
    text = REVISION.sub('', text)
    pattern = r'(<rule\b[^>]*\bid="110001"[^>]*>.*?<description>)(.*?)(</description>)'
    text, count = re.subn(pattern, lambda m: m[1] + m[2].rstrip() + ' [hc-rev:' + '0' * 64 + ']' + m[3], text, flags=re.S)
    if count != 1:
        raise ValueError('Expected exactly one 110001 classifier description to stamp')
    digest = sha256(text.encode()).hexdigest()
    return text.replace('[hc-rev:' + '0' * 64 + ']', f'[hc-rev:{digest}]')


def rule_revision(text):
    text = text.replace('\r\n', '\n')
    markers = REVISION.findall(text)
    if len(markers) != 1 or sha256(REVISION.sub('[hc-rev:' + '0' * 64 + ']', text).encode()).hexdigest() != markers[0]:
        raise ValueError('Rules revision missing or stale; stamp the candidate before installing it')
    description = ET.fromstring(text).find("rule[@id='110001']/description")
    if description is None or markers[0] not in (description.text or ''):
        raise ValueError('Revision must be in the loaded authentication classifier description')
    return markers[0]


def snapshot_files(paths):
    return {str(path.resolve()): sha256(path.read_bytes()).hexdigest() for path in paths}


def verify_snapshot(snapshot):
    if any(not Path(path).is_file() or sha256(Path(path).read_bytes()).hexdigest() != digest for path, digest in snapshot.items()):
        raise ValueError('Rules, configuration or executable changed during native validation')


def check_transcript(output, expected, revision=None):
    blocks = PHASE_ONE.split(INFO_PREFIX.sub('', output))[1:]
    ids, descriptions = [], []
    for block in blocks:
        phase = re.split(r'(?m)^\*\*Phase 3: Completed filtering \(rules\)\.\s*$', block)
        matches = re.findall(r"(?m)^\s*id: '([0-9]+)'", phase[1]) if len(phase) == 2 else []
        ids.append(matches[0] if len(matches) == 1 else None)
        if len(phase) == 2:
            descriptions.extend(re.findall(r"(?m)^\s*description: '(.*)'", phase[1]))
    disrupted = re.search(r'(?m)^(?:' + LOG_PREFIX + r'\[(?:WARNING|ERROR)\] )?'
                          r'(?:New session was created with token|\*\* Wazuh-logtest error)', output)
    passed = len(blocks) == len(expected) and ids == expected and disrupted is None
    if revision is not None:
        passed = passed and any(f'[hc-rev:{revision}]' in description for description in descriptions)
    return {'expected_rules': expected, 'observed_rules': ids, 'passed': passed,
            'revision_verified': passed if revision is not None else False}


def expiry_metadata(name, output):
    """Reconstruct the actual inputs, session and processing times from native replies."""
    action, outcome, rule, count = EXPIRY_CASES[name]
    expected = [rule] * count
    if not check_transcript(output, expected)['passed']:
        raise ValueError('Unexpected Phase 3 sequence')
    human_events = re.findall(r"(?m)^\s*full event: '(.*)'$", INFO_PREFIX.sub('', output))
    replies = REPLY_LINE.findall(output)
    if len(human_events) != count or len(replies) != count:
        raise ValueError('Missing or additional engine replies or full events')
    ids, stamps, instants = [], [], []
    tokens, actors = set(), set()
    for raw, human in zip(replies, human_events):
        packet = json.loads(raw)
        data = packet['data']
        native = data['output']
        source = json.loads(native['full_log'])
        decoded = native['data']
        identity, actor, token = source['event_id'], source['actor_key'], data['token']
        if (packet['error'] != 0 or data['codemsg'] < 0 or native['rule']['id'] != rule
                or source != json.loads(human) or source['service'] != 'hospital-lab'
                or source['action'] != action or source['outcome'] != outcome
                or not isinstance(actor, str) or not actor or not isinstance(token, str) or not token
                or str(UUID(identity)) != identity or decoded['event_id'] != identity
                or decoded['actor_key'] != actor):
            raise ValueError('Engine input, decoded identity, session or rule mismatch')
        stamp = native['timestamp']
        instant = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
        if instant.utcoffset() is None:
            raise ValueError('Missing engine time zone')
        ids.append(identity)
        stamps.append(stamp)
        instants.append(instant)
        tokens.add(token)
        actors.add(actor)
    if len(set(ids)) != count or len(actors) != 1 or len(tokens) != 1:
        raise ValueError('Repeated event, actor change or session rollover')
    if (instants != sorted(instants) or (instants[-2] - instants[0]).total_seconds() > 60
            or (instants[-1] - instants[-2]).total_seconds() <= 60):
        raise ValueError('Engine times do not show a compact prefix and a gap above 60 seconds')
    return {'event_ids': ids, 'engine_times': stamps, 'session_sha256': sha256(tokens.pop().encode()).hexdigest()}


def validate_expiry_transcript(name, output, case_result):
    try:
        metadata = expiry_metadata(name, output)
        return all(case_result.get(key) == value for key, value in metadata.items())
    except (ValueError, KeyError, AttributeError, TypeError, OverflowError):
        return False


def installed_config(executable, rules):
    root = executable.resolve().parent.parent
    config = root / 'etc/ossec.conf'
    text = re.sub(r'<\?xml[^>]*\?>', '', config.read_text(encoding='utf-8'))
    tree = ET.fromstring('<root>' + text + '</root>')
    exclusions = {node.text.strip() for node in tree.findall('.//ruleset/rule_exclude') if node.text}
    included = any(rules.resolve().parent == (root / node.text.strip()).resolve()
                   for node in tree.findall('.//ruleset/rule_dir') if node.text)
    included = included or any(rules.resolve() == (root / node.text.strip()).resolve()
                               for node in tree.findall('.//ruleset/rule_include') if node.text)
    if not included or rules.name in exclusions:
        raise ValueError('The selected candidate is not enabled by this installation configuration')
    return config


def event(action, **fields):
    return {'service': 'hospital-lab', 'schema_version': 1, 'event_id': str(uuid4()),
            'run_id': str(uuid4()), 'actor_key': 'unit-actor|10.77.0.10',
            'action': action, 'outcome': 'success', **fields}


def cases():
    result = []
    for count in [4, 5, 6]:
        result.append((f'auth-{count}', [(0, event('login_failure', outcome='denied')) for _ in range(count)],
                       ['110001'] * min(count, 4) + (['110101'] if count >= 5 else []) + (['110001'] if count == 6 else [])))
    result.append(('auth-expiry', [(0, event('login_failure', outcome='denied')) for _ in range(4)]
                   + [(65, event('login_failure', outcome='denied'))], ['110001'] * 5))
    result.append(('auth-two-actors', [(0, event('login_failure', actor_key=f'actor-{i % 2}|10.77.0.10')) for i in range(8)], ['110001'] * 8))
    for count in [19, 20, 21]:
        result.append((f'reads-{count}', [(0, event('record_read', care_scope='assigned')) for _ in range(count)],
                       ['110002'] * min(count, 19) + (['110103'] if count >= 20 else []) + (['110002'] if count == 21 else [])))
        result.append((f'writes-{count}', [(0, event('document_update')) for _ in range(count)],
                       ['110003'] * min(count, 19) + (['110201'] if count >= 20 else []) + (['110003'] if count == 21 else [])))
    result.append(('unassigned-read', [(0, event('record_read', care_scope='unassigned'))], ['110102']))
    result.append(('unassigned-burst', [(0, event('record_read', care_scope='unassigned')) for _ in range(20)], ['110102'] * 19 + ['110103']))
    result.append(('repeated-same-patient', [(0, event('record_read', care_scope='assigned', patient_id='P0001')) for _ in range(20)], ['110002'] * 19 + ['110103']))
    for name, action, base in [('reads', 'record_read', '110002'), ('writes', 'document_update', '110003')]:
        result.append((f'{name}-actor-separation', [(0, event(action, actor_key=f'actor-{i % 2}|10.77.0.10')) for i in range(38)], [base] * 38))
        result.append((f'{name}-expiry', [(0, event(action)) for _ in range(19)] + [(65, event(action))], [base] * 20))
    result.append(('denied-reads', [(0, event('record_denied', outcome='denied')) for _ in range(20)], ['110000'] * 20))
    result.append(('failed-writes', [(0, event('document_update', outcome='failure')) for _ in range(20)], ['110000'] * 20))
    result.append(('failed-transfer', [(0, event('export_failed', outcome='failure', bytes_sent=5000000, destination_approved='no'))], ['110000']))
    for size in [999999, 1000000, 1000001]:
        result.append((f'export-{size}', [(0, event('export_completed', destination_approved='no', bytes_sent=size))],
                       ['110301' if size < 1000000 else '110302']))
    result.append(('approved-large-export', [(0, event('export_completed', destination_approved='yes', bytes_sent=5000000))], ['110004']))
    return result
