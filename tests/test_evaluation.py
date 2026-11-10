import json
from pathlib import Path

import pytest

from hospital_soc.evaluate import evaluate_run
from evidence_fixtures import evidence_bundle


def unit_packet_verifier(monkeypatch, rows):
    # Explicit unit seam for tshark, not a replacement used by the lab CLI.
    monkeypatch.setattr('hospital_soc.evaluate.verified_packet_rows', lambda *args: rows, raising=False)


def test_complete_unit_fixture_reconciles_with_stubbed_external_packet_decoder(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] == 'complete', result


def test_exact_fim_root_and_digests_reconcile_in_unit_fixture(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] == 'complete', result
    assert result['fim_correlated_files'] == 50


def test_delayed_archives_cannot_be_hidden_by_declared_zero_index_delay(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    archive = [json.loads(line) for line in (tmp_path / 'archives.jsonl').read_text().splitlines()]
    archive[0]['timestamp'] = '2026-10-22T01:00:00Z'
    (tmp_path / 'archives.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in archive))
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert any('collection' in issue.lower() or 'archive' in issue.lower() for issue in result['issues'])


def test_corrupt_magic_only_capture_cannot_pass_with_an_unrelated_csv(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    (tmp_path / 'traffic.pcapng').write_bytes(bytes.fromhex('0a0d0d0a') + b'\0' * 24)
    assert evaluate_run(manifest, tmp_path)['status'] != 'complete'


def test_fim_same_basename_in_wrong_directory_is_not_correlated(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text().splitlines()]
    for event in alerts:
        if 'syscheck' in event:
            event['syscheck']['path'] = event['syscheck']['path'].replace('/hospital/documents/', '/different/documents/')
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts))
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert result['fim_correlated_files'] == 0


def test_nested_null_or_scalar_evidence_is_invalid_not_a_crash(tmp_path):
    manifest, rows = evidence_bundle(tmp_path)
    (tmp_path / 'archives.jsonl').write_text('{"data":null}\n')
    assert evaluate_run(manifest, tmp_path)['status'] == 'invalid'


def test_prior_run_quiet_interval_is_required_and_checked(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    observations = json.loads((tmp_path / 'observations.json').read_text())
    observations.update(first_measured_run=False, previous_measured_run_id='00000000-0000-0000-0000-000000000002',
                        prior_run_final_manager_at='2026-10-21T23:59:55Z', quiet_interval_started_at='2026-10-21T23:59:56Z')
    (tmp_path / 'observations.json').write_text(json.dumps(observations))
    assert evaluate_run(manifest, tmp_path)['status'] != 'complete'


def test_missing_artifacts_are_incomplete_not_clean(tmp_path):
    manifest = {'run_id': '00000000-0000-0000-0000-000000000001', 'scenario': 's1',
                'status': 'generated', 'receipts': [], 'policy_mode': 'observe',
                'started_at': '2026-10-22T00:00:00Z', 'ended_at': '2026-10-22T00:01:00Z', 'notes': []}
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] == 'incomplete'
    assert 'app.jsonl' in result['missing_evidence']
    assert result['attack_detection_passed'] is False
    assert result['collection_coverage'] is None


def test_generator_failure_and_malformed_manifest_cannot_pass(tmp_path):
    assert evaluate_run({'status': 'invalid'}, tmp_path)['status'] == 'invalid'
    assert evaluate_run({}, tmp_path)['status'] == 'invalid'


def test_diagnostic_runs_cannot_be_live_acceptance(tmp_path):
    manifest = {'run_id': '00000000-0000-0000-0000-000000000001', 'scenario': 's1',
                'status': 'generated', 'receipts': [], 'policy_mode': 'observe',
                'started_at': '2026-10-22T00:00:00Z', 'ended_at': '2026-10-22T00:01:00Z',
                'notes': ['Diagnostic timing: sleeps skipped; not a measured acceptance run.']}
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] == 'incomplete'
    assert 'diagnostic_timing' in result['issues']


def test_empty_or_corrupt_sources_remain_visible(tmp_path):
    manifest = {'run_id': '00000000-0000-0000-0000-000000000001', 'scenario': 's1',
                'status': 'generated', 'receipts': [], 'policy_mode': 'observe',
                'started_at': '2026-10-22T00:00:00Z', 'ended_at': '2026-10-22T00:01:00Z', 'notes': []}
    (tmp_path / 'app.jsonl').write_text('not json\n')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] == 'invalid'
    assert any('app.jsonl' in issue for issue in result['issues'])


def test_incomplete_baseline_cannot_receive_complete(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    manifest['metadata'].pop('intent', None)
    unit_packet_verifier(monkeypatch, rows)
    assert evaluate_run(manifest, tmp_path)['status'] != 'complete'


def test_failed_receipt_cannot_receive_complete(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    manifest['receipts'][0]['status'] = 500
    unit_packet_verifier(monkeypatch, rows)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert any('status' in issue or 'operation' in issue for issue in result['issues'])


@pytest.mark.parametrize('bad_id', [None, [], {}, '', 'not-a-uuid'])
def test_malformed_receipt_identity_returns_invalid(tmp_path, monkeypatch, bad_id):
    manifest, rows = evidence_bundle(tmp_path)
    manifest['receipts'][0]['request_id'] = bad_id
    unit_packet_verifier(monkeypatch, rows)
    assert evaluate_run(manifest, tmp_path)['status'] == 'invalid'


def test_source_and_archives_before_run_cannot_receive_complete(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    from datetime import datetime, timedelta
    for name in ['app.jsonl', 'archives.jsonl']:
        values = [json.loads(line) for line in (tmp_path / name).read_text().splitlines()]
        for value in values:
            data = value.get('data', value)
            data['event_time'] = (datetime.fromisoformat(data['event_time'].replace('Z', '+00:00')) - timedelta(hours=1)).isoformat()
            if 'timestamp' in value:
                value['timestamp'] = (datetime.fromisoformat(value['timestamp'].replace('Z', '+00:00')) - timedelta(hours=1)).isoformat()
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in values))
    unit_packet_verifier(monkeypatch, rows)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert 'Source event lies outside the run interval' in result['issues']


def test_missing_native_cases_cannot_receive_complete(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    proof = json.loads((tmp_path / 'native-rule-tests.json').read_text())
    proof['cases'] = []
    (tmp_path / 'native-rule-tests.json').write_text(json.dumps(proof))
    unit_packet_verifier(monkeypatch, rows)
    assert evaluate_run(manifest, tmp_path)['status'] != 'complete'


def test_missing_normal_workflow_is_rejected_even_with_matching_archives(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    remove = {r['request_id'] for r in manifest['receipts'] if r['path'] == '/api/exports'}
    manifest['receipts'] = [r for r in manifest['receipts'] if r['request_id'] not in remove]
    for name in ['app.jsonl', 'archives.jsonl']:
        values = [json.loads(line) for line in (tmp_path / name).read_text().splitlines()]
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in values if item.get('data', item)['request_id'] not in remove))
    unit_packet_verifier(monkeypatch, rows)
    result = evaluate_run(manifest, tmp_path)
    assert result['collection_coverage'] == 1
    assert result['status'] != 'complete'
    assert any('operation counts' in issue for issue in result['issues'])


def test_receipt_target_disagreement_cannot_pass(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    receipt = next(r for r in manifest['receipts'] if r['path'].startswith('/api/records/'))
    receipt['path'] = '/api/records/P0200'
    unit_packet_verifier(monkeypatch, rows)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert any('operation counts' in issue for issue in result['issues'])


def test_document_response_results_cannot_be_omitted(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, 's2')
    for receipt in manifest['receipts']:
        receipt['result'] = {}
    unit_packet_verifier(monkeypatch, rows)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert any('required response' in issue.lower() for issue in result['issues'])


@pytest.mark.parametrize('field,value', [('sha256_after', []), ('transfer_id', 'not-a-uuid'), ('bytes_sent', True)])
def test_response_result_fields_require_correct_types(tmp_path, monkeypatch, field, value):
    manifest, rows = evidence_bundle(tmp_path, 's2')
    manifest['receipts'][0]['result'][field] = value
    unit_packet_verifier(monkeypatch, rows)
    assert evaluate_run(manifest, tmp_path)['status'] == 'invalid'


def test_native_proof_cannot_supply_its_own_expectations(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    proof = json.loads((tmp_path / 'native-rule-tests.json').read_text())
    for case in proof['cases']:
        case['expected_rules'] = case['observed_rules'] = ['110101']
    (tmp_path / 'native-rule-tests.json').write_text(json.dumps(proof))
    unit_packet_verifier(monkeypatch, rows)
    assert evaluate_run(manifest, tmp_path)['status'] != 'complete'


def test_malformed_native_snapshot_cannot_pass(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    proof = json.loads((tmp_path / 'native-rule-tests.json').read_text())
    proof['snapshot'] = {'a': None, 'b': [], 'c': {}}
    (tmp_path / 'native-rule-tests.json').write_text(json.dumps(proof))
    unit_packet_verifier(monkeypatch, rows)
    assert evaluate_run(manifest, tmp_path)['status'] != 'complete'


def test_idle_tail_cannot_disguise_compressed_baseline(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    for receipt in manifest['receipts']:
        receipt['started_at'], receipt['ended_at'] = '2026-10-22T00:00:01Z', '2026-10-22T00:00:01.050Z'
    for name in ['app.jsonl', 'archives.jsonl']:
        values = [json.loads(line) for line in (tmp_path / name).read_text().splitlines()]
        for value in values:
            value.get('data', value)['event_time'] = '2026-10-22T00:00:01.010Z'
            if 'timestamp' in value:
                value['timestamp'] = '2026-10-22T00:00:02Z'
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in values))
    unit_packet_verifier(monkeypatch, rows)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert any('schedule' in issue.lower() for issue in result['issues'])
