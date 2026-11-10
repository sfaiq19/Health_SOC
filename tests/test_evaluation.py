import json
from pathlib import Path
from uuid import uuid4

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


def _mutate_s2_app_hashes(tmp_path, manifest, doc_ids, sha_before='a' * 64, sha_after='b' * 64):
    target = set(doc_ids)
    for receipt in manifest['receipts']:
        if receipt.get('method') == 'PUT' and receipt.get('result', {}).get('document_id') in target:
            receipt['result']['sha256_before'] = sha_before
            receipt['result']['sha256_after'] = sha_after

    for name in ['app.jsonl', 'archives.jsonl', 'alerts.jsonl']:
        items = [json.loads(line) for line in (tmp_path / name).read_text(encoding='utf-8').splitlines() if line.strip()]
        for item in items:
            data = item.get('data', item)
            if data.get('action') == 'document_update' and data.get('document_id') in target:
                data['sha256_before'] = sha_before
                data['sha256_after'] = sha_after
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items), encoding='utf-8')


def test_s2_single_document_application_hash_mismatch_reduces_corroboration(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    _mutate_s2_app_hashes(tmp_path, manifest, ['D001'], sha_before='a' * 64, sha_after='b' * 64)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert result['fim_correlated_files'] == 49
    assert 'Application document update digests disagree with inventory or FIM evidence' in result['issues']
    assert 'FIM digest corroboration incomplete; manual path/time fallback is not auto-accepted' in result['issues']


def test_s2_all_documents_application_hash_mismatch_fails_evaluation(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    all_docs = [f'D{i:03}' for i in range(1, 51)]
    _mutate_s2_app_hashes(tmp_path, manifest, all_docs, sha_before='a' * 64, sha_after='b' * 64)
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert result['fim_correlated_files'] == 0
    assert 'Application document update digests disagree with inventory or FIM evidence' in result['issues']
    assert 'FIM digest corroboration incomplete; manual path/time fallback is not auto-accepted' in result['issues']


def test_s2_contradictory_fim_observation_prevents_corroboration(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    alerts.append({
        'agent': {'name': 'hospital-win'},
        'timestamp': '2026-10-22T00:00:10Z',
        'syscheck': {
            'path': 'C:/Lab/hospital/documents/D001.txt',
            'sha256_before': 'c' * 64,
            'sha256_after': 'd' * 64,
        }
    })
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert result['fim_correlated_files'] == 49
    assert 'Contradictory or duplicate FIM observations detected' in result['issues']


def test_s2_duplicate_fim_observation_prevents_corroboration(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    first_fim = next(item for item in alerts if item.get('syscheck', {}).get('path', '').endswith('D001.txt'))
    alerts.append(dict(first_fim))
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert result['fim_correlated_files'] == 49
    assert 'Contradictory or duplicate FIM observations detected' in result['issues']


def test_s2_missing_or_duplicate_application_updates_prevent_corroboration(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    manifest['receipts'] = [r for r in manifest['receipts'] if r.get('result', {}).get('document_id') != 'D001']
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert result['fim_correlated_files'] == 49
    assert 'Missing or duplicate application document updates' in result['issues']


def test_s2_unchanged_document_hash_yields_integer_correlation_count(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    before = json.loads((tmp_path / 'file-hashes-before.json').read_text(encoding='utf-8'))
    after = json.loads((tmp_path / 'file-hashes-after.json').read_text(encoding='utf-8'))
    after['D001'] = before['D001']
    (tmp_path / 'file-hashes-after.json').write_text(json.dumps(after), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert result['fim_correlated_files'] == 49
    assert isinstance(result['fim_correlated_files'], int)


def test_s2_fim_missing_extension_does_not_corroborate(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    for item in alerts:
        if item.get('syscheck', {}).get('path', '').endswith('D001.txt'):
            item['syscheck']['path'] = item['syscheck']['path'].removesuffix('.txt')
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert result['fim_correlated_files'] == 49
    assert 'Contradictory or duplicate FIM observations detected' in result['issues']


def test_actionable_alert_with_wrong_agent_name_is_rejected(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    actionable = next(item for item in alerts if str(item.get('rule', {}).get('id')) == '110201')
    actionable['agent']['name'] = 'other-host'
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert result['observed_rules'] == []
    assert result['attack_detection_passed'] is False
    assert result['alert_latencies_s'] == []
    assert 'Actionable alert does not reconcile with its source event' in result['issues']


def test_actionable_alert_with_missing_agent_is_rejected(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    actionable = next(item for item in alerts if str(item.get('rule', {}).get('id')) == '110201')
    actionable.pop('agent', None)
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert result['observed_rules'] == []
    assert result['attack_detection_passed'] is False
    assert result['alert_latencies_s'] == []
    assert 'Actionable alert does not reconcile with its source event' in result['issues']


def test_actionable_alert_with_unrelated_request_id_is_rejected(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    actionable = next(item for item in alerts if str(item.get('rule', {}).get('id')) == '110201')
    actionable['data']['request_id'] = str(uuid4())
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert result['observed_rules'] == []
    assert result['attack_detection_passed'] is False
    assert result['alert_latencies_s'] == []
    assert 'Actionable alert does not reconcile with its source event' in result['issues']


def test_actionable_alert_with_omitted_request_id_is_rejected(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    actionable = next(item for item in alerts if str(item.get('rule', {}).get('id')) == '110201')
    actionable['data'].pop('request_id', None)
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete'
    assert result['observed_rules'] == []
    assert result['attack_detection_passed'] is False
    assert result['alert_latencies_s'] == []
    assert 'Actionable alert does not reconcile with its source event' in result['issues']
    assert result['fim_correlated_files'] == 50


def test_unrelated_background_run_alerts_do_not_affect_evaluation(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    actionable = next(item for item in alerts if str(item.get('rule', {}).get('id')) == '110201')
    bg_alert = json.loads(json.dumps(actionable))
    bg_alert['data']['run_id'] = str(uuid4())
    bg_alert['agent'] = {'name': 'other-host'}
    bg_alert['data']['request_id'] = str(uuid4())
    alerts.append(bg_alert)
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] == 'complete', result
    assert result['observed_rules'] == ['110201']
    assert len(result['alert_latencies_s']) == 1
    assert 'Actionable alert does not reconcile with its source event' not in result['issues']


@pytest.mark.parametrize('mutation', ['wrong_agent', 'unrelated_request_id', 'missing_request_id'])
def test_mixed_valid_and_invalid_target_run_alerts(tmp_path, monkeypatch, mutation):
    manifest, rows = evidence_bundle(tmp_path, scenario='s2')
    unit_packet_verifier(monkeypatch, rows)
    alerts = [json.loads(line) for line in (tmp_path / 'alerts.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    actionable = next(item for item in alerts if str(item.get('rule', {}).get('id')) == '110201')
    invalid_alert = json.loads(json.dumps(actionable))
    if mutation == 'wrong_agent':
        invalid_alert['agent'] = {'name': 'other-host'}
    elif mutation == 'unrelated_request_id':
        invalid_alert['data']['request_id'] = str(uuid4())
    elif mutation == 'missing_request_id':
        invalid_alert['data'].pop('request_id', None)
    alerts.append(invalid_alert)
    (tmp_path / 'alerts.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in alerts), encoding='utf-8')
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert result['observed_rules'] == ['110201']
    assert len(result['alert_latencies_s']) == 1
    assert 'Actionable alert does not reconcile with its source event' in result['issues']


def test_baseline_multi_pair_laboratory_orders_and_results_bind_successfully(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    app_events = [json.loads(line) for line in (tmp_path / 'app.jsonl').read_text().splitlines() if line.strip()]
    lab_orders = [e for e in app_events if e.get('action') == 'lab_order_created']
    lab_results = [e for e in app_events if e.get('action') == 'lab_result_created']
    assert len(lab_orders) == 5
    assert len(lab_results) == 5
    for order, result_event in zip(lab_orders, lab_results):
        assert order['order_id'] == result_event['order_id']
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] == 'complete', result
    assert result['issues'] == []


def test_baseline_lab_result_missing_order_id_in_event_fails(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    for name in ['app.jsonl', 'archives.jsonl']:
        items = [json.loads(line) for line in (tmp_path / name).read_text().splitlines() if line.strip()]
        for item in items:
            data = item.get('data', item)
            if data.get('action') == 'lab_result_created':
                data.pop('order_id', None)
                break
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items))
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert 'Laboratory result does not reconcile with its preceding planned order' in result['issues']


@pytest.mark.parametrize('target', [
    'order_receipt_order_id',
    'order_event_order_id',
    'result_receipt_result_id',
    'result_event_result_id',
])
def test_baseline_lab_missing_required_ids_fails(tmp_path, monkeypatch, target):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    if target == 'order_receipt_order_id':
        receipt = next(r for r in manifest['receipts'] if r.get('path') == '/api/lab/orders')
        receipt['result'].pop('order_id', None)
    elif target == 'order_event_order_id':
        for name in ['app.jsonl', 'archives.jsonl']:
            items = [json.loads(line) for line in (tmp_path / name).read_text().splitlines() if line.strip()]
            for item in items:
                data = item.get('data', item)
                if data.get('action') == 'lab_order_created':
                    data.pop('order_id', None)
                    break
            (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items))
    elif target == 'result_receipt_result_id':
        receipt = next(r for r in manifest['receipts'] if r.get('path') == '/api/lab/results')
        receipt['result'].pop('result_id', None)
    elif target == 'result_event_result_id':
        for name in ['app.jsonl', 'archives.jsonl']:
            items = [json.loads(line) for line in (tmp_path / name).read_text().splitlines() if line.strip()]
            for item in items:
                data = item.get('data', item)
                if data.get('action') == 'lab_result_created':
                    data.pop('result_id', None)
                    break
            (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items))
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert 'Laboratory result does not reconcile with its preceding planned order' in result['issues']


def test_baseline_lab_result_unknown_order_id_fails(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    unknown_id = '00000000-0000-0000-0000-000000999999'
    for name in ['app.jsonl', 'archives.jsonl']:
        items = [json.loads(line) for line in (tmp_path / name).read_text().splitlines() if line.strip()]
        for item in items:
            data = item.get('data', item)
            if data.get('action') == 'lab_result_created':
                data['order_id'] = unknown_id
                break
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items))
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert 'Laboratory result does not reconcile with its preceding planned order' in result['issues']


def test_baseline_lab_result_order_from_another_run_fails(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    foreign_order_id = '00000000-0000-0000-0000-000000888888'
    foreign_run_id = '00000000-0000-0000-0000-000000777777'
    for name in ['app.jsonl', 'archives.jsonl']:
        items = [json.loads(line) for line in (tmp_path / name).read_text().splitlines() if line.strip()]
        for item in items:
            data = item.get('data', item)
            if data.get('action') == 'lab_result_created':
                data['order_id'] = foreign_order_id
                break
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items))
    app_items = [json.loads(line) for line in (tmp_path / 'app.jsonl').read_text().splitlines() if line.strip()]
    first_order = next(item for item in app_items if item.get('action') == 'lab_order_created')
    foreign_order = dict(first_order)
    foreign_order['run_id'] = foreign_run_id
    foreign_order['event_id'] = str(uuid4())
    foreign_order['request_id'] = str(uuid4())
    foreign_order['order_id'] = foreign_order_id
    app_items.append(foreign_order)
    (tmp_path / 'app.jsonl').write_text(''.join(json.dumps(item) + '\n' for item in app_items))

    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert 'Laboratory result does not reconcile with its preceding planned order' in result['issues']


def test_baseline_lab_result_swapped_order_ids_fails(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    app_items = [json.loads(line) for line in (tmp_path / 'app.jsonl').read_text().splitlines() if line.strip()]
    lab_results = [e for e in app_items if e.get('action') == 'lab_result_created']
    order_id_0 = lab_results[0]['order_id']
    order_id_1 = lab_results[1]['order_id']

    for name in ['app.jsonl', 'archives.jsonl']:
        items = [json.loads(line) for line in (tmp_path / name).read_text().splitlines() if line.strip()]
        res_count = 0
        for item in items:
            data = item.get('data', item)
            if data.get('action') == 'lab_result_created':
                if res_count == 0:
                    data['order_id'] = order_id_1
                elif res_count == 1:
                    data['order_id'] = order_id_0
                res_count += 1
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items))

    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert 'Laboratory result does not reconcile with its preceding planned order' in result['issues']


def test_baseline_lab_result_reused_order_id_fails(tmp_path, monkeypatch):
    manifest, rows = evidence_bundle(tmp_path)
    unit_packet_verifier(monkeypatch, rows)
    app_items = [json.loads(line) for line in (tmp_path / 'app.jsonl').read_text().splitlines() if line.strip()]
    lab_results = [e for e in app_items if e.get('action') == 'lab_result_created']
    first_order_id = lab_results[0]['order_id']

    for name in ['app.jsonl', 'archives.jsonl']:
        items = [json.loads(line) for line in (tmp_path / name).read_text().splitlines() if line.strip()]
        res_count = 0
        for item in items:
            data = item.get('data', item)
            if data.get('action') == 'lab_result_created':
                if res_count == 1:
                    data['order_id'] = first_order_id
                res_count += 1
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items))

    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert 'Laboratory result does not reconcile with its preceding planned order' in result['issues']
