from dataclasses import dataclass
from hashlib import sha256
import json
from uuid import uuid4

import requests
from flask import Blueprint, current_app, g, jsonify, abort

from .auth import body_object, require_roles, text_field
from .config import LabConfig
from .store import database

bp = Blueprint('exports', __name__)


@dataclass(frozen=True)
class TransferReceipt:
    transfer_id: str
    received_bytes: int
    sha256: str
    received_at: str


def build_payload(config: LabConfig, size: int) -> bytes:
    if type(size) is not int or not 1 <= size <= 10000000:
        raise ValueError('Export body limit is 1–10000000 bytes')
    with database(config) as db:
        patients = [dict(row) for row in db.execute('SELECT * FROM patients ORDER BY id')]
    envelope = {'synthetic': True, 'records': patients, 'synthetic_attachment': ''}
    encoded = json.dumps(envelope, separators=(',', ':')).encode('utf-8')
    padding = size - len(encoded)
    if padding < 0:
        raise ValueError('Requested body is too small for the synthetic record bundle')
    envelope['synthetic_attachment'] = 'X' * padding
    payload = json.dumps(envelope, separators=(',', ':')).encode('utf-8')
    assert len(payload) == size
    return payload


def send_export(config: LabConfig, destination_id: str, payload: bytes, transfer_id: str, run_id: str) -> TransferReceipt:
    destination = config.destinations[destination_id]
    if not 1 <= len(payload) <= 10000000:
        raise ValueError('Export body exceeds receiver limit')
    key = json.loads((config.root / 'secrets.json').read_text())['receiver_key']
    digest = sha256(payload).hexdigest()
    with requests.Session() as session:
        session.trust_env = False
        response = session.post(f'http://{destination.host}:{destination.port}/receive',
                                data=payload, timeout=(3, 15), allow_redirects=False,
                                headers={'Content-Type': 'application/json', 'X-Transfer-ID': transfer_id,
                                         'X-Payload-SHA256': digest, 'X-Lab-Receiver-Key': key,
                                         'X-Lab-Run-ID': run_id})
    if response.status_code != 201:
        raise ValueError(f'Receiver did not confirm storage: HTTP {response.status_code}')
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError('Malformed receiver receipt')
    if (value.get('transfer_id') != transfer_id or type(value.get('received_bytes')) is not int
            or value['received_bytes'] != len(payload) or value.get('sha256') != digest
            or not isinstance(value.get('received_at'), str)):
        raise ValueError('Receiver receipt differs from sent body')
    return TransferReceipt(**{field: value[field] for field in ['transfer_id', 'received_bytes', 'sha256', 'received_at']})


@bp.post('/api/exports')
@require_roles('records')
def export():
    cfg = current_app.extensions['lab']
    body = body_object()
    identity = text_field(body, 'destination_id')
    if identity not in cfg.destinations:
        abort(400, 'Unknown lab destination ID')
    destination = cfg.destinations[identity]
    g.details.update(destination_id=identity, destination_approved='yes' if destination.approved else 'no',
                     destination_ip=destination.host, destination_port=destination.port)
    if cfg.policy_mode == 'enforce' and not destination.approved:
        g.action = 'export_denied'
        abort(403)
    try:
        payload = build_payload(cfg, body.get('bytes'))
    except ValueError as error:
        abort(400, str(error))
    transfer_id = str(uuid4())
    g.details.update(transfer_id=transfer_id)
    current_app.extensions['emit']('operation_intent', 'success', 200,
                                   {'operation': 'export', 'transfer_id': transfer_id, 'destination_id': identity})
    try:
        receipt = send_export(cfg, identity, payload, transfer_id, g.run_id)
    except (requests.RequestException, ValueError, KeyError):
        g.action, g.outcome = 'export_failed', 'failure'
        return jsonify(error='Transfer not confirmed by independent receiver', transfer_id=transfer_id), 502
    g.action = 'export_completed'
    g.details.update(bytes_sent=receipt.received_bytes, payload_sha256=receipt.sha256)
    return jsonify(transfer_id=transfer_id, bytes_sent=receipt.received_bytes, payload_sha256=receipt.sha256)
