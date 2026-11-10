"""Shared native expectations, transcript checks and revision provenance."""
from hashlib import sha256
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from uuid import uuid4

REVISION = re.compile(r'\[hc-rev:([0-9a-f]{64})\]')


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
    blocks = re.split(r'\*\*Phase 1:', output)[1:]
    ids, descriptions = [], []
    for block in blocks:
        phase = block.split('**Phase 3:', 1)
        matches = re.findall(r"(?m)^\s*id: '([0-9]+)'", phase[1]) if len(phase) == 2 else []
        ids.append(matches[0] if len(matches) == 1 else None)
        descriptions.extend(re.findall(r"(?m)^\s*description: '(.*)'", block))
    passed = len(blocks) == len(expected) and ids == expected
    if revision is not None:
        passed = passed and any(f'[hc-rev:{revision}]' in description for description in descriptions)
    return {'expected_rules': expected, 'observed_rules': ids, 'passed': passed,
            'revision_verified': passed if revision is not None else False}


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
    result.append(('auth-expiry', [(0, event('login_failure')) for _ in range(4)] + [(61, event('login_failure'))], ['110001'] * 5))
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
        result.append((f'{name}-expiry', [(0, event(action)) for _ in range(19)] + [(61, event(action))], [base] * 20))
    result.append(('denied-reads', [(0, event('record_denied', outcome='denied')) for _ in range(20)], ['110000'] * 20))
    result.append(('failed-writes', [(0, event('document_update', outcome='failure')) for _ in range(20)], ['110000'] * 20))
    result.append(('failed-transfer', [(0, event('export_failed', outcome='failure', bytes_sent=5000000, destination_approved='no'))], ['110000']))
    for size in [999999, 1000000, 1000001]:
        result.append((f'export-{size}', [(0, event('export_completed', destination_approved='no', bytes_sent=size))],
                       ['110301' if size < 1000000 else '110302']))
    result.append(('approved-large-export', [(0, event('export_completed', destination_approved='yes', bytes_sent=5000000))], ['110004']))
    return result
