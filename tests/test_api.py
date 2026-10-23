import json
import sqlite3
from dataclasses import replace

import pytest

from hospital_soc.app import create_app


def test_seed_and_health_have_real_state(lab, headers):
    response = lab.client.get('/health', headers=headers())
    assert response.status_code == 200
    assert response.json['status'] == 'ok'
    with sqlite3.connect(lab.cfg.root / 'hospital.sqlite') as db:
        assert db.execute('select count(*) from patients').fetchone()[0] == 200
        assert db.execute('select count(*) from devices').fetchone()[0] == 10
    assert len(list((lab.cfg.root / 'documents').glob('*.txt'))) == 50


def test_credentials_roles_and_care_modes(lab, headers, login):
    token = login()
    assert lab.client.get('/api/records/P0001', headers=headers(token)).status_code == 200
    assert lab.client.get('/api/records/P0100', headers=headers(token)).status_code == 200
    enforced = create_app(replace(lab.cfg, policy_mode='enforce')).test_client()
    assert enforced.get('/api/records/P0100', headers=headers(token)).status_code == 403
    clerk = login('records-clerk')
    assert lab.client.get('/api/records/P0001', headers=headers(clerk)).status_code == 403
    assert lab.client.get('/api/records/P0001', headers=headers()).status_code == 401


def test_bad_login_does_not_issue_session(lab, headers):
    result = lab.client.post('/api/auth/login', headers=headers(), json={
        'username': 'clinician', 'password': 'wrong', 'actor_role': 'administrator'})
    assert result.status_code == 401
    assert 'token' not in result.json


def test_laboratory_order_and_result_are_persisted(lab, headers, login):
    clinician = login()
    order = lab.client.post('/api/lab/orders', headers=headers(clinician), json={
        'patient_id': 'P0001', 'test': 'synthetic-cbc'})
    assert order.status_code == 201
    tech = login('lab-technician')
    result = lab.client.post('/api/lab/results', headers=headers(tech), json={
        'order_id': order.json['order_id'], 'value': 'synthetic-normal'})
    assert result.status_code == 201
    with sqlite3.connect(lab.cfg.root / 'hospital.sqlite') as db:
        assert db.execute('select count(*) from lab_results').fetchone()[0] == 1
    assert lab.client.post('/api/lab/results', headers=headers(clinician), json={}).status_code == 403


def test_device_credentials_cannot_cross_identities_or_human_routes(lab, headers):
    token = lab.secrets['devices']['device-01']
    assert lab.client.post('/api/devices/device-01/telemetry', headers=headers(token),
                           json={'value': 70, 'unit': 'synthetic'}).status_code == 201
    assert lab.client.post('/api/devices/device-02/telemetry', headers=headers(token),
                           json={'value': 70}).status_code == 403
    assert lab.client.get('/api/records/P0001', headers=headers(token)).status_code == 403


@pytest.mark.parametrize('body', [None, [], 'invalid', {'username': ['bad']}, {'username': 'x' * 500}])
def test_malformed_login_payloads_are_rejected(lab, headers, body):
    result = lab.client.post('/api/auth/login', headers=headers(), json=body)
    assert result.status_code in (400, 415)


def test_uuid_headers_validated_and_echoed(lab, headers):
    h = headers()
    response = lab.client.get('/health', headers=h)
    assert response.headers['X-Request-ID'] == h['X-Request-ID']
    assert lab.client.get('/api/records/P0001', headers={'X-Lab-Run-ID': 's1'}).status_code == 400


def test_expired_session_is_rejected(lab, headers, login):
    token = login()
    with sqlite3.connect(lab.cfg.root / 'hospital.sqlite') as db:
        db.execute('update sessions set expires_at=0')
    assert lab.client.get('/api/records/P0001', headers=headers(token)).status_code == 401


def test_fake_forwarded_address_and_actor_are_not_trusted(lab, headers, login):
    h = headers(login())
    h['X-Forwarded-For'] = '8.8.8.8'
    lab.client.get('/api/records/P0100', headers=h)
    events = [json.loads(x) for x in (lab.cfg.root / 'logs/app.jsonl').read_text().splitlines()]
    assert events[-1]['source_ip'] == '127.0.0.1'
    assert events[-1]['actor_id'] == 'clinician'
    assert events[-1]['care_scope'] == 'unassigned'
