import json
import subprocess
import sys


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
