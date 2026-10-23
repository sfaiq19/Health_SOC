import json


def test_audit_has_unique_ids_and_no_patient_bodies_or_credentials(lab, headers, login):
    token = login()
    for _ in range(3):
        lab.client.get('/api/records/P0001', headers=headers(token))
    text = (lab.cfg.root / 'logs/app.jsonl').read_text()
    events = [json.loads(x) for x in text.splitlines()]
    assert len({x['event_id'] for x in events}) == len(events)
    assert all(x['schema_version'] == 1 and x['service'] == 'hospital-lab' for x in events)
    assert token not in text
    assert lab.secrets['passwords']['clinician'] not in text
    assert all(len(line.encode()) < 8192 for line in text.splitlines())
    assert 'Synthetic Patient' not in text


def test_audit_failure_prevents_clinical_mutation(lab, headers, login, monkeypatch):
    token = login()
    def fail(*args, **kwargs):
        raise OSError('simulated full disk')
    monkeypatch.setattr(lab.app.extensions['audit'], 'write', fail)
    response = lab.client.post('/api/lab/orders', headers=headers(token),
                               json={'patient_id': 'P0001', 'test': 'synthetic-cbc'})
    assert response.status_code == 503
    import sqlite3
    with sqlite3.connect(lab.cfg.root / 'hospital.sqlite') as db:
        assert db.execute('select count(*) from lab_orders').fetchone()[0] == 0
