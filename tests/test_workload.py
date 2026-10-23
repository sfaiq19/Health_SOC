import json

import pytest
from werkzeug.serving import make_server
from threading import Thread

from hospital_soc.workload import run_baseline, planned_operations


@pytest.fixture
def live_server(lab):
    server = make_server('127.0.0.1', 0, lab.app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_port}'
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_planned_operations_are_reproducible_and_cover_hospital_modules():
    first = planned_operations(60, 101)
    assert first == planned_operations(60, 101)
    assert first != planned_operations(60, 102)
    assert {'records', 'laboratory', 'devices', 'health', 'documents'} <= {x['kind'] for x in first}


def test_baseline_makes_real_requests_without_label_leakage(lab, live_server, tmp_path):
    result = run_baseline(lab.cfg, duration_s=1, seed=101, base_url=live_server,
                          output=tmp_path / 'run', diagnostic=True)
    assert result.status == 'generated'
    assert result.receipts
    assert result.run_id
    assert (tmp_path / 'run/manifest.json').is_file()
    lines = (lab.cfg.root / 'logs/app.jsonl').read_text()
    assert 'is_attack' not in lines and 'scenario' not in lines
    assert all('token' not in x for x in result.receipts)


def test_failed_required_operation_keeps_manifest_invalid(lab, tmp_path):
    result = run_baseline(lab.cfg, duration_s=1, seed=101, base_url='http://127.0.0.1:65530',
                          output=tmp_path / 'run', diagnostic=True)
    assert result.status == 'invalid'
    assert json.loads((tmp_path / 'run/manifest.json').read_text())['status'] == 'invalid'
