"""Run real wazuh-logtest sessions; no Python rule emulator is used."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import subprocess
import threading
import time

from hospital_soc.native_validation import (cases, event, stamp_revision, rule_revision,
    check_transcript, installed_config, snapshot_files, verify_snapshot)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--stamp-rules', type=Path, help='Stamp a candidate revision; does not run native tests')
    parser.add_argument('--executable', type=Path, default=Path('/var/ossec/bin/wazuh-logtest'))
    parser.add_argument('--rules', type=Path, default=Path('/var/ossec/etc/rules/healthcare_rules.xml'))
    args = parser.parse_args()
    if args.stamp_rules:
        args.stamp_rules.write_text(stamp_revision(args.stamp_rules.read_text(encoding='utf-8')), encoding='utf-8', newline='\n')
        print('Candidate stamped. Install it, then run native validation; no native proof was produced.')
        return 0
    if not args.output:
        parser.error('--output is required for native validation')
    if not args.executable.is_file() or not args.rules.is_file():
        raise SystemExit('Install Wazuh and copy the rules first. No native validation has occurred.')
    args.output.mkdir(parents=True, exist_ok=True)
    proof = args.output / 'native-rule-tests.json'
    if proof.exists():
        raise SystemExit('Preserve the existing proof and use a fresh validation directory.')
    config = installed_config(args.executable, args.rules)
    revision = rule_revision(args.rules.read_text(encoding='utf-8'))
    snapshot = snapshot_files([args.rules, config, args.executable])
    original_rules = args.rules.read_bytes()
    version = subprocess.run([str(args.executable), '-V'], capture_output=True, text=True, timeout=15)
    version_text = version.stdout + version.stderr
    if not re.search(r'\bv?4\.14\.\d+\b', version_text):
        raise SystemExit('Expected a recorded Wazuh 4.14.x installation; native validation did not run')
    results = []
    canary = ('loaded-revision', [(0, event('login_failure'))], ['110001'])
    for name, sequence, expected in [canary, *cases()]:
        verify_snapshot(snapshot)
        chunks = []
        process = subprocess.Popen([str(args.executable), '-v'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
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
        checked = check_transcript(output, expected, revision if name == 'loaded-revision' else None)
        checked['passed'] = checked['passed'] and code == 0
        results.append({'case': name, **checked})
        print(json.dumps(results[-1]), flush=True)
        verify_snapshot(snapshot)
        if name == 'loaded-revision' and not checked['passed']:
            break
    verify_snapshot(snapshot)
    (args.output / 'healthcare_rules.xml').write_bytes(original_rules)
    result = {'validation_schema': 2, 'engine': 'wazuh-logtest', 'rules_sha256': sha256(original_rules).hexdigest(),
              'loaded_revision': revision, 'version': version_text.strip(), 'snapshot': snapshot,
              'rules_path': str(args.rules.resolve()), 'config_path': str(config.resolve()),
              'executable_path': str(args.executable.resolve()),
              'success': all(item['passed'] for item in results), 'cases': results}
    proof.write_text(json.dumps(result, indent=2), encoding='utf-8')
    return 0 if result['success'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
