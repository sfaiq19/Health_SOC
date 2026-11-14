"""Run real wazuh-logtest sessions; no Python rule emulator is used."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from queue import Empty, Queue
import re
import subprocess
import threading
import time

from hospital_soc.native_validation import (EXPIRY_CASES, REPLY_LINE, cases, event, stamp_revision, rule_revision,
    check_transcript, expiry_metadata, installed_config, snapshot_files, verify_snapshot)


def run_case(executable, sequence, timed):
    """Use one CLI session. For expiry, wait for each actual engine reply before continuing."""
    command = [str(executable), '-v']
    if timed:
        command.append('-d')
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='strict')
    if not timed:
        payload = ''.join(json.dumps(value) + '\n' for _, value in sequence)
        try:
            output, _ = process.communicate(payload, timeout=60)
            return output, process.returncode, None
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()
            return output, -1, 'Timed out waiting for Wazuh'

    chunks, replies = [], Queue()

    def read_output():
        try:
            for line in process.stdout:
                chunks.append(line)
                match = REPLY_LINE.match(line)
                if match:
                    replies.put(match.group(1))
        finally:
            replies.put(None)

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    error = None
    try:
        for delay, value in sequence:
            if delay:
                time.sleep(delay)
            process.stdin.write(json.dumps(value) + '\n')
            process.stdin.flush()
            raw = replies.get(timeout=45)
            if raw is None:
                raise ValueError('Wazuh exited before acknowledging the event')
            packet = json.loads(raw)
            native = packet['data']['output']
            if (packet['error'] != 0 or packet['data']['codemsg'] < 0
                    or json.loads(native['full_log']) != value
                    or native['data']['event_id'] != value['event_id']):
                raise ValueError('Engine did not acknowledge the submitted event')
    except Empty:
        error = 'Timed out waiting for the engine reply'
    except (OSError, KeyError, TypeError, ValueError) as exc:
        error = str(exc)
    finally:
        try:
            process.stdin.close()
        except OSError:
            error = 'Wazuh closed its input'
        try:
            code = process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            code, error = -1, 'Timed out closing Wazuh'
        reader.join(timeout=5)
        if reader.is_alive():
            error = 'Wazuh transcript did not close'
    return ''.join(chunks), code, error


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
    try:
        args.output.mkdir(parents=True, exist_ok=False, mode=0o700)
    except FileExistsError:
        raise SystemExit('Preserve the existing directory and use a fresh validation directory.')
    proof = args.output / 'native-rule-tests.json'
    config = installed_config(args.executable, args.rules)
    revision = rule_revision(args.rules.read_text(encoding='utf-8'))
    snapshot = snapshot_files([args.rules, config, args.executable])
    original_rules = args.rules.read_bytes()
    version = subprocess.run([str(args.executable), '-V'], capture_output=True, text=True, timeout=15)
    version_text = version.stdout + version.stderr
    if not re.search(r'\bv?4\.14\.\d+\b', version_text):
        raise SystemExit('Expected a recorded Wazuh 4.14.x installation; native validation did not run')
    results, expiry_sessions = [], set()
    canary = ('loaded-revision', [(0, event('login_failure'))], ['110001'])
    for name, sequence, expected in [canary, *cases()]:
        verify_snapshot(snapshot)
        timed = name in EXPIRY_CASES
        output, code, error = run_case(args.executable, sequence, timed)
        raw = output.encode()
        (args.output / f'{name}.txt').write_bytes(raw)
        checked = check_transcript(output, expected, revision if name == 'loaded-revision' else None)
        checked['transcript_sha256'] = sha256(raw).hexdigest()
        if timed:
            try:
                checked.update(expiry_metadata(name, output))
                if checked['session_sha256'] in expiry_sessions:
                    raise ValueError('Wazuh reused an independent expiry session')
                expiry_sessions.add(checked['session_sha256'])
            except (ValueError, KeyError, TypeError, AttributeError, OverflowError) as exc:
                error = error or str(exc)
        checked['passed'] = checked['passed'] and code == 0 and error is None
        if error:
            checked['error'] = error
        results.append({'case': name, **checked})
        print(json.dumps(results[-1]), flush=True)
        verify_snapshot(snapshot)
        if name == 'loaded-revision' and not checked['passed']:
            break
    verify_snapshot(snapshot)
    (args.output / 'healthcare_rules.xml').write_bytes(original_rules)
    result = {'validation_schema': 3, 'engine': 'wazuh-logtest', 'rules_sha256': sha256(original_rules).hexdigest(),
              'loaded_revision': revision, 'version': version_text.strip(), 'snapshot': snapshot,
              'rules_path': str(args.rules.resolve()), 'config_path': str(config.resolve()),
              'executable_path': str(args.executable.resolve()),
              'success': all(item['passed'] for item in results), 'cases': results}
    proof.write_text(json.dumps(result, indent=2), encoding='utf-8')
    return 0 if result['success'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
