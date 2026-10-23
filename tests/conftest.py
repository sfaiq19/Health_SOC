import json
import shutil
from types import SimpleNamespace
from uuid import uuid4

import pytest

from hospital_soc.app import create_app
from hospital_soc.config import LabConfig
from hospital_soc.store import seed_lab


@pytest.fixture(scope='session')
def seed_template(tmp_path_factory):
    root = tmp_path_factory.mktemp('seed') / 'runtime'
    seed_lab(LabConfig(root=root), seed=101)
    return root


@pytest.fixture
def lab(tmp_path, seed_template):
    root = tmp_path / 'runtime'
    shutil.copytree(seed_template, root)
    cfg = LabConfig(root=root)
    app = create_app(cfg)
    app.config['TESTING'] = True
    secrets = json.loads((root / 'secrets.json').read_text())
    return SimpleNamespace(cfg=cfg, app=app, client=app.test_client(), secrets=secrets, run_id=str(uuid4()))


@pytest.fixture
def headers(lab):
    def build(token=None):
        value = {'X-Lab-Run-ID': lab.run_id, 'X-Request-ID': str(uuid4())}
        if token:
            value['Authorization'] = 'Bearer ' + token
        return value
    return build


@pytest.fixture
def login(lab, headers):
    def perform(actor='clinician'):
        response = lab.client.post('/api/auth/login', json={
            'username': actor, 'password': lab.secrets['passwords'][actor],
        }, headers=headers())
        assert response.status_code == 200
        return response.json['token']
    return perform
