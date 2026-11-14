import json
import subprocess
import sys
import pytest


def test_cli_seed_creates_real_runtime_without_printing_credentials(tmp_path):
    root = tmp_path / 'standalone'
    result = subprocess.run([sys.executable, '-m', 'hospital_soc', '--runtime', str(root),
                             'seed', '--seed', '101'], text=True, capture_output=True,
                            env=__import__('os').environ | {'PYTHONPATH': 'src'})
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)['patients'] == 200
    assert (root / 'hospital.sqlite').exists()
    assert 'passwords' not in result.stdout


def test_cli_corrupt_manifest_writes_invalid_metrics(tmp_path):
    (tmp_path / 'manifest.json').write_text('not JSON')
    result = subprocess.run([sys.executable, '-m', 'hospital_soc', 'evaluate', '--run-dir', str(tmp_path)],
                            text=True, capture_output=True,
                            env=__import__('os').environ | {'PYTHONPATH': 'src'})
    assert result.returncode == 2
    assert json.loads((tmp_path / 'metrics.json').read_text())['status'] == 'invalid'


def test_cli_malformed_nested_receipt_writes_invalid_metrics(tmp_path):
    from evidence_fixtures import evidence_bundle
    manifest, _ = evidence_bundle(tmp_path)
    manifest['receipts'][0]['request_id'] = []
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    result = subprocess.run([sys.executable, '-m', 'hospital_soc', 'evaluate', '--run-dir', str(tmp_path)],
                            text=True, capture_output=True,
                            env=__import__('os').environ | {'PYTHONPATH': 'src'})
    assert result.returncode == 2
    assert json.loads((tmp_path / 'metrics.json').read_text())['status'] == 'invalid'


@pytest.mark.parametrize('bad_id', [[], {}])
def test_cli_malformed_source_document_id_writes_invalid_metrics(tmp_path, bad_id):
    from evidence_fixtures import evidence_bundle
    manifest, _ = evidence_bundle(tmp_path, 's2')
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest))
    source = tmp_path / 'app.jsonl'
    events = [json.loads(line) for line in source.read_text().splitlines()]
    next(e for e in events if e['action'] == 'document_update')['document_id'] = bad_id
    source.write_text(''.join(json.dumps(e) + '\n' for e in events))
    result = subprocess.run([sys.executable, '-m', 'hospital_soc', 'evaluate', '--run-dir', str(tmp_path)],
                            text=True, capture_output=True,
                            env=__import__('os').environ | {'PYTHONPATH': 'src'})
    assert result.returncode == 2, result.stderr
    metrics = json.loads((tmp_path / 'metrics.json').read_text())
    assert metrics['status'] == 'invalid'
    assert any('document_id' in issue for issue in metrics['issues'])


def test_cli_contradictory_evidence_bundle_writes_incomplete_metrics_and_returns_nonzero(tmp_path):
    from evidence_fixtures import evidence_bundle
    manifest, _ = evidence_bundle(tmp_path, 's2')
    for receipt in manifest['receipts']:
        if receipt.get('method') == 'PUT' and 'document_id' in receipt.get('result', {}):
            receipt['result']['sha256_before'] = 'a' * 64
            receipt['result']['sha256_after'] = 'b' * 64
    for name in ['app.jsonl', 'archives.jsonl', 'alerts.jsonl']:
        items = [json.loads(line) for line in (tmp_path / name).read_text(encoding='utf-8').splitlines() if line.strip()]
        for item in items:
            data = item.get('data', item)
            if data.get('action') == 'document_update':
                data['sha256_before'] = 'a' * 64
                data['sha256_after'] = 'b' * 64
        (tmp_path / name).write_text(''.join(json.dumps(item) + '\n' for item in items), encoding='utf-8')
    (tmp_path / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')

    result = subprocess.run([sys.executable, '-m', 'hospital_soc', 'evaluate', '--run-dir', str(tmp_path)],
                            text=True, capture_output=True,
                            env=__import__('os').environ | {'PYTHONPATH': 'src'})
    assert result.returncode != 0
    metrics = json.loads((tmp_path / 'metrics.json').read_text(encoding='utf-8'))
    assert metrics['status'] == 'incomplete'
    assert metrics['fim_correlated_files'] == 0
    assert 'Application document update digests disagree with inventory or FIM evidence' in metrics['issues']


def test_cli_restore_writes_exclusive_timestamped_receipt_with_50_hashes(tmp_path):
    root = tmp_path / 'hospital'
    receipt_path = tmp_path / 'receipts' / 'reset-001.json'
    env = __import__('os').environ | {'PYTHONPATH': 'src'}
    seed_res = subprocess.run([sys.executable, '-m', 'hospital_soc', '--runtime', str(root),
                               'seed', '--seed', '101'], text=True, capture_output=True, env=env)
    assert seed_res.returncode == 0, seed_res.stderr
    (root / 'documents' / 'D001.txt').write_bytes(b'mutated during s2')

    res = subprocess.run([sys.executable, '-m', 'hospital_soc', '--runtime', str(root),
                          'restore', '--receipt', str(receipt_path)], text=True, capture_output=True, env=env)
    assert res.returncode == 0, res.stderr
    receipt = json.loads(receipt_path.read_text(encoding='utf-8'))
    seed_manifest = json.loads((root / 'seed-manifest.json').read_text(encoding='utf-8'))
    assert receipt['verified'] is True
    assert receipt['restored'] == 50
    assert receipt['seed'] == 101
    assert receipt['hashes'] == seed_manifest['documents']
    assert receipt['receipt_path'] == str(receipt_path)

    overwrite_attempt = subprocess.run([sys.executable, '-m', 'hospital_soc', '--runtime', str(root),
                                        'restore', '--receipt', str(receipt_path)], text=True, capture_output=True, env=env)
    assert overwrite_attempt.returncode != 0
