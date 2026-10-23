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
