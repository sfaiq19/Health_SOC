"""Run isolated real wazuh-logtest sessions; never substitutes a Python rule emulator."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shutil
import subprocess
import threading
import time
from uuid import uuid4


def event(action, **fields):
    return {'service': 'hospital-lab', 'schema_version': 1, 'event_id': str(uuid4()),
            'run_id': str(uuid4()), 'actor_key': 'unit-actor|10.77.0.10',
            'action': action, 'outcome': 'success', **fields}


def cases():
    result = []
    for count in [4, 5, 6]:
        result.append((f'auth-{count}', [(0, event('login_failure', outcome='denied')) for _ in range(count)],
                       '110101' if count >= 5 else '110001'))
    result.append(('auth-expiry', [(0, event('login_failure')) for _ in range(4)] + [(61, event('login_failure'))], '110001'))
    result.append(('auth-two-actors', [(0, event('login_failure', actor_key=f'actor-{i % 2}|10.77.0.10')) for i in range(8)], '110001'))
    for count in [19, 20, 21]:
        result.append((f'reads-{count}', [(0, event('record_read', care_scope='assigned')) for _ in range(count)],
                       '110103' if count >= 20 else '110002'))
        result.append((f'writes-{count}', [(0, event('document_update')) for _ in range(count)],
                       '110201' if count >= 20 else '110003'))
    result.append(('unassigned-read', [(0, event('record_read', care_scope='unassigned'))], '110102'))
    result.append(('unassigned-burst', [(0, event('record_read', care_scope='unassigned')) for _ in range(20)], '110103'))
    result.append(('repeated-same-patient', [(0, event('record_read', care_scope='assigned', patient_id='P0001')) for _ in range(20)], '110103'))
    for name, action, base in [('reads', 'record_read', '110002'), ('writes', 'document_update', '110003')]:
        result.append((f'{name}-actor-separation', [(0, event(action, actor_key=f'actor-{i % 2}|10.77.0.10')) for i in range(38)], base))
        result.append((f'{name}-expiry', [(0, event(action)) for _ in range(19)] + [(61, event(action))], base))
    result.append(('denied-reads', [(0, event('record_denied', outcome='denied')) for _ in range(20)], '110000'))
    result.append(('failed-writes', [(0, event('document_update', outcome='failure')) for _ in range(20)], '110000'))
    result.append(('failed-transfer', [(0, event('export_failed', outcome='failure', bytes_sent=5000000, destination_approved='no'))], '110000'))
    for size in [999999, 1000000, 1000001]:
        result.append((f'export-{size}', [(0, event('export_completed', destination_approved='no', bytes_sent=size))],
                       '110301' if size < 1000000 else '110302'))
    result.append(('approved-large-export', [(0, event('export_completed', destination_approved='yes', bytes_sent=5000000))], '110004'))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--executable', type=Path, default=Path('/var/ossec/bin/wazuh-logtest'))
    parser.add_argument('--rules', type=Path, default=Path('/var/ossec/etc/rules/healthcare_rules.xml'))
    args = parser.parse_args()
    if not args.executable.is_file() or not args.rules.is_file():
        raise SystemExit('Install Wazuh and copy the rules first. No native validation has occurred.')
    args.output.mkdir(parents=True, exist_ok=True)
    proof = args.output / 'native-rule-tests.json'
    if proof.exists():
        raise SystemExit('Preserve the existing proof and use a fresh validation directory.')
    results = []
    for name, sequence, expected in cases():
        chunks = []
        process = subprocess.Popen([str(args.executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
        reader = threading.Thread(target=lambda: chunks.append(process.stdout.read()), daemon=True)
        reader.start()
        try:
            for delay, value in sequence:
                time.sleep(delay)
                process.stdin.write(json.dumps(value) + '\n')
                process.stdin.flush()
            process.stdin.close()
            code = process.wait(timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait()
            code = -1
        reader.join(timeout=5)
        output = ''.join(chunks)
        (args.output / f'{name}.txt').write_text(output, encoding='utf-8')
        ids = re.findall(r"(?m)^\s*id: '([0-9]+)'", output)
        actual = ids[-1] if ids else None
        results.append({'case': name, 'expected_last_rule': expected, 'last_rule': actual,
                        'passed': code == 0 and actual == expected})
        print(json.dumps(results[-1]), flush=True)
    shutil.copyfile(args.rules, args.output / 'healthcare_rules.xml')
    result = {'engine': 'wazuh-logtest', 'rules_sha256': sha256(args.rules.read_bytes()).hexdigest(),
              'success': all(item['passed'] for item in results), 'cases': results}
    proof.write_text(json.dumps(result, indent=2), encoding='utf-8')
    return 0 if result['success'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
