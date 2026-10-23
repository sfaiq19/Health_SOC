import json
from hashlib import sha256

from hospital_soc.scenarios import run_scenario
from test_workload import live_server


def test_s1_makes_failed_logins_then_thirty_real_reads(lab, live_server, tmp_path):
    manifest = run_scenario(lab.cfg, 's1', seed=201, output=tmp_path / 's1',
                            base_url=live_server, diagnostic=True)
    assert manifest.status == 'generated'
    assert len([r for r in manifest.receipts if r['status'] == 401]) == 6
    reads = [r for r in manifest.receipts if r['path'].startswith('/api/records/')]
    assert len(reads) == 30 and len({r['path'] for r in reads}) == 30
    assert all(r['status'] == 200 for r in reads)
    logs = (lab.cfg.root / 'logs/app.jsonl').read_text()
    assert 'scenario' not in logs and 'is_attack' not in logs


def test_s2_changes_all_fifty_files_and_saves_independent_hashes(lab, live_server, tmp_path):
    output = tmp_path / 's2'
    manifest = run_scenario(lab.cfg, 's2', seed=202, output=output, base_url=live_server, diagnostic=True)
    assert manifest.status == 'generated'
    before = json.loads((output / 'file-hashes-before.json').read_text())
    after = json.loads((output / 'file-hashes-after.json').read_text())
    assert len(before) == 50 and all(before[x] != after[x] for x in before)
    assert not (lab.cfg.root / '.run.lock').exists()
    assert after['D001'] == sha256((lab.cfg.root / 'documents/D001.txt').read_bytes()).hexdigest()


def test_scenario_refuses_overlapping_run(lab, live_server, tmp_path):
    (lab.cfg.root / '.run.lock').write_text('active')
    import pytest
    with pytest.raises(FileExistsError):
        run_scenario(lab.cfg, 's1', seed=201, output=tmp_path / 's1', base_url=live_server, diagnostic=True)


def test_mitigation_run_observes_actual_server_policy(lab, tmp_path):
    from dataclasses import replace
    from hospital_soc.app import create_app
    from threading import Thread
    from werkzeug.serving import make_server
    server = make_server('127.0.0.1', 0, create_app(replace(lab.cfg, policy_mode='enforce')), threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_scenario(lab.cfg, 's1', seed=201, output=tmp_path / 'enforce',
                              base_url=f'http://127.0.0.1:{server.server_port}', diagnostic=True)
        assert result.status == 'generated'
        assert result.policy_mode == 'enforce'
        reads = [receipt for receipt in result.receipts if receipt['path'].startswith('/api/records/')]
        assert len(reads) == 30 and all(receipt['status'] == 403 for receipt in reads)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
