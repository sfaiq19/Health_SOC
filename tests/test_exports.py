from dataclasses import replace
from hashlib import sha256
import json
from threading import Thread

import pytest
from werkzeug.serving import make_server

from hospital_soc.app import create_app
from hospital_soc.config import Destination
from hospital_soc.receiver import ReceiverConfig, create_receiver


@pytest.fixture
def receivers(lab, tmp_path):
    servers = []
    destinations = {}
    roots = {}
    for identity, approved in [('approved-lab', True), ('unapproved-lab', False)]:
        root = tmp_path / identity
        app = create_receiver(ReceiverConfig(root=root, key='test-receiver-key'))
        server = make_server('127.0.0.1', 0, app, threaded=True)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        destinations[identity] = Destination('127.0.0.1', server.server_port, approved)
        roots[identity] = root
    secrets = json.loads((lab.cfg.root / 'secrets.json').read_text())
    secrets['receiver_key'] = 'test-receiver-key'
    (lab.cfg.root / 'secrets.json').write_text(json.dumps(secrets))
    lab.cfg = replace(lab.cfg, destinations=destinations)
    lab.app = create_app(lab.cfg)
    lab.client = lab.app.test_client()
    yield roots
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize('size', [999999, 1000000, 1000001, 5000000])
def test_real_exports_have_independent_matching_receiver_bytes(lab, receivers, headers, login, size):
    result = lab.client.post('/api/exports', headers=headers(login('records-clerk')),
                             json={'destination_id': 'unapproved-lab', 'bytes': size})
    assert result.status_code == 200
    received = receivers['unapproved-lab'] / (result.json['transfer_id'] + '.bin')
    assert len(received.read_bytes()) == size
    assert sha256(received.read_bytes()).hexdigest() == result.json['payload_sha256']


def test_enforced_export_never_reaches_unapproved_receiver(lab, receivers, headers, login):
    client = create_app(replace(lab.cfg, policy_mode='enforce')).test_client()
    result = client.post('/api/exports', headers=headers(login('records-clerk')),
                          json={'destination_id': 'unapproved-lab', 'bytes': 5000000})
    assert result.status_code == 403
    assert not list(receivers['unapproved-lab'].glob('*.bin'))


@pytest.mark.parametrize('body', [{'destination_id': 'http://example.com', 'bytes': 100000},
                                {'destination_id': 'approved-lab', 'bytes': 10000001},
                                {'destination_id': 'approved-lab', 'bytes': -1},
                                {'destination_id': 'approved-lab', 'bytes': True}])
def test_export_boundaries_rejected_before_send(lab, receivers, headers, login, body):
    result = lab.client.post('/api/exports', headers=headers(login('records-clerk')), json=body)
    assert result.status_code == 400
    assert not list(receivers['approved-lab'].glob('*.bin'))


def test_receiver_failure_never_logs_completed_export(lab, headers, login):
    client = create_app(replace(lab.cfg, destinations={
        'approved-lab': Destination('127.0.0.1', 65530, True)})).test_client()
    result = client.post('/api/exports', headers=headers(login('records-clerk')),
                          json={'destination_id': 'approved-lab', 'bytes': 250000})
    assert result.status_code == 502
    events = [json.loads(x) for x in (lab.cfg.root / 'logs/app.jsonl').read_text().splitlines()]
    assert events[-1]['action'] == 'export_failed'
    assert not any(x['action'] == 'export_completed' for x in events)


@pytest.mark.parametrize('status', [201, 302])
def test_false_receiver_receipt_or_redirect_is_not_success(lab, headers, login, monkeypatch, status):
    import requests
    from types import SimpleNamespace
    def bad_receipt(self, url, **kwargs):
        return SimpleNamespace(status_code=status, json=lambda: {
            'transfer_id': kwargs['headers']['X-Transfer-ID'], 'received_bytes': len(kwargs['data']) + 1,
            'sha256': kwargs['headers']['X-Payload-SHA256'], 'received_at': '2026-10-22T00:00:00Z'})
    monkeypatch.setattr(requests.Session, 'post', bad_receipt)
    result = lab.client.post('/api/exports', headers=headers(login('records-clerk')),
                             json={'destination_id': 'approved-lab', 'bytes': 250000})
    assert result.status_code == 502
    assert 'export_completed' not in (lab.cfg.root / 'logs/app.jsonl').read_text()


def test_s3_generator_transfers_real_five_megabyte_bundle(lab, receivers, tmp_path):
    from hospital_soc.scenarios import run_scenario
    server = make_server('127.0.0.1', 0, lab.app, threaded=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_scenario(lab.cfg, 's3', seed=203, output=tmp_path / 's3',
                              base_url=f'http://127.0.0.1:{server.server_port}', diagnostic=True)
        assert result.status == 'generated'
        objects = list(receivers['unapproved-lab'].glob('*.bin'))
        assert len(objects) == 1 and objects[0].stat().st_size == 5000000
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize('receipt', [[], None, {'unexpected': 'shape'}])
def test_malformed_receiver_receipt_is_a_failed_export(lab, headers, login, monkeypatch, receipt):
    import requests
    from types import SimpleNamespace
    monkeypatch.setattr(requests.Session, 'post', lambda *args, **kwargs:
                        SimpleNamespace(status_code=201, json=lambda: receipt))
    response = lab.client.post('/api/exports', headers=headers(login('records-clerk')),
                               json={'destination_id': 'approved-lab', 'bytes': 250000})
    assert response.status_code == 502


def test_receiver_storage_failure_does_not_acknowledge_or_publish(tmp_path, monkeypatch):
    from pathlib import Path
    from uuid import uuid4
    root = tmp_path / 'receiver'
    client = create_receiver(ReceiverConfig(root, 'test-receiver-key')).test_client()
    original = Path.open
    def fail_part(path, *args, **kwargs):
        if path.parent == root and path.suffix == '.part':
            raise OSError('simulated full disk')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'open', fail_part)
    response = client.post('/receive', data=b'payload', headers={
        'X-Lab-Receiver-Key': 'test-receiver-key', 'X-Transfer-ID': str(uuid4()),
        'X-Payload-SHA256': sha256(b'payload').hexdigest()})
    assert response.status_code == 503
    assert not list(root.glob('*.bin')) and not (root / 'receiver.jsonl').exists()
