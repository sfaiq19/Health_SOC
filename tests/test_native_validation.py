"""Wrapper/provenance tests; none of these simulate successful native acceptance."""
import importlib.util
import json
from pathlib import Path

import pytest


def driver():
    spec = importlib.util.spec_from_file_location('native_driver', 'scripts/verify-native-rules.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def transcript(ids, description='Hospital classification'):
    return ''.join("**Phase 1: Completed pre-decoding.\n**Phase 2: Completed decoding.\n"
                   "**Phase 3: Completed filtering (rules).\n"
                   f"    id: '{identity}'\n    description: '{description}'\n" for identity in ids)


def test_native_expectations_include_post_burst_base_event():
    cases = {name: expected for name, _, expected in driver().cases()}
    assert cases['auth-6'] == ['110001'] * 4 + ['110101', '110001']
    assert cases['reads-21'] == ['110002'] * 19 + ['110103', '110002']
    assert cases['writes-21'] == ['110003'] * 19 + ['110201', '110003']


def test_transcript_rejects_early_false_positive_and_missing_results():
    module = driver()
    assert module.check_transcript(transcript(['110101', '110001']), ['110001', '110001'])['passed'] is False
    assert module.check_transcript(transcript(['110001']), ['110001', '110001'])['passed'] is False
    assert module.check_transcript(transcript(['110001', '110001']), ['110001', '110001'])['passed'] is True


def test_debug_transcript_reads_only_native_phase_lines():
    prefix = '2026-11-13 12:00:00,123 wazuh_logtest[INFO] '
    output = ''.join(prefix + line for line in transcript(['110001']).splitlines(keepends=True))
    assert driver().check_transcript(output, ['110001'])['passed']
    assert not driver().check_transcript('DEBUG Reply: ' + repr(output), ['110001'])['passed']


@pytest.mark.parametrize('marker', ['New session was created with token "replacement"',
                                    '** Wazuh-logtest error when connecting with wazuh-analysisd'])
def test_nonexpiry_case_rejects_reset_or_processing_error(marker):
    output = transcript(['110001']) + marker + '\n' + transcript(['110001'])
    assert not driver().check_transcript(output, ['110001', '110001'])['passed']


def test_rules_revision_is_bound_to_content_and_loaded_description():
    module = driver()
    stamped = module.stamp_revision(Path('siem/healthcare_rules.xml').read_text())
    revision = module.rule_revision(stamped)
    assert module.check_transcript(transcript(['110001'], f'login [hc-rev:{revision}]'), ['110001'], revision)['passed']
    assert not module.check_transcript(transcript(['110001'], 'old revision'), ['110001'], revision)['passed']
    with pytest.raises(ValueError):
        module.rule_revision(stamped.replace('frequency="5"', 'frequency="7"'))


def test_rules_snapshot_cannot_change_during_validation(tmp_path):
    module = driver()
    rules = tmp_path / 'rules.xml'
    rules.write_text('original')
    snapshot = module.snapshot_files([rules])
    rules.write_text('changed')
    with pytest.raises(ValueError):
        module.verify_snapshot(snapshot)


def test_driver_does_not_certify_old_loaded_revision(tmp_path, monkeypatch):
    import subprocess
    import sys
    module = driver()
    root = tmp_path / 'installation'
    executable = root / 'bin/wazuh-logtest'
    executable.parent.mkdir(parents=True)
    executable.write_text('isolated test executable placeholder')
    rules = root / 'etc/rules/healthcare_rules.xml'
    rules.parent.mkdir(parents=True)
    rules.write_text(module.stamp_revision(Path('siem/healthcare_rules.xml').read_text()))
    (root / 'etc/ossec.conf').write_text('<ossec_config><ruleset><rule_dir>etc/rules</rule_dir></ruleset></ossec_config>')
    class OldEngine:
        def __init__(self, *args, **kwargs):
            self.returncode = 0
        def communicate(self, *args, **kwargs):
            return transcript(['110001'], 'old loaded revision'), None
    monkeypatch.setattr(module.subprocess, 'Popen', OldEngine)
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a, 0, 'Wazuh v4.14.0', ''))
    monkeypatch.setattr(module.time, 'sleep', lambda *a: None)
    output = tmp_path / 'proof'
    monkeypatch.setattr(sys, 'argv', ['driver', '--output', str(output), '--executable', str(executable), '--rules', str(rules)])
    assert module.main() == 2
    proof = json.loads((output / 'native-rule-tests.json').read_text())
    assert proof['success'] is False
    assert proof['cases'][0]['revision_verified'] is False
    with pytest.raises(SystemExit, match='fresh validation directory'):
        module.main()


@pytest.mark.parametrize('corrupt_ack', [False, True])
def test_expiry_pause_follows_matching_engine_reply(monkeypatch, corrupt_ack):
    """Exercise the real pipe/reader with a CLI fixture; never build a native proof."""
    import subprocess
    import sys
    module = driver()
    engine = r"""
import json, sys
for line in sys.stdin:
    source = json.loads(line)
    seen = source.copy()
    if sys.argv[1] == 'True':
        seen['event_id'] = 'not-the-input'
    packet = {'error': 0, 'data': {'codemsg': 0, 'output': {'full_log': line, 'data': seen}}}
    print('2026-11-13 00:00:00,000 wazuh_logtest[DEBUG] Reply: ' + json.dumps(packet), flush=True)
"""
    start = subprocess.Popen
    monkeypatch.setattr(module.subprocess, 'Popen', lambda cmd, **kw: start(
        [sys.executable, '-u', '-c', engine, str(corrupt_ack)], **kw))
    waits = []
    monkeypatch.setattr(module.time, 'sleep', waits.append)
    sequence = [(0, module.event('login_failure')), (65, module.event('login_failure'))]
    output, code, error = module.run_case(Path('fixture'), sequence, True)
    assert code == 0
    if corrupt_ack:
        assert waits == []
        assert error and 'acknowledge' in error
        assert output.count('[DEBUG] Reply:') == 1
    else:
        assert waits == [65]
        assert error is None
        assert output.count('[DEBUG] Reply:') == 2


def test_candidate_outside_effective_ruleset_is_refused(tmp_path):
    module = driver()
    executable = tmp_path / 'bin/wazuh-logtest'
    executable.parent.mkdir()
    executable.write_text('test')
    config = tmp_path / 'etc/ossec.conf'
    config.parent.mkdir()
    config.write_text('<ossec_config><ruleset><rule_dir>etc/rules</rule_dir></ruleset></ossec_config>')
    candidate = tmp_path / 'unloaded.xml'
    candidate.write_text('<group/>')
    with pytest.raises(ValueError, match='not enabled'):
        module.installed_config(executable, candidate)
