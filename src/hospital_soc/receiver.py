from dataclasses import dataclass
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import threading
from uuid import UUID

from flask import Flask, jsonify, request, abort
from werkzeug.exceptions import HTTPException

from .audit import utc_now
from .store import reject_links

_locks = {}


@dataclass(frozen=True)
class ReceiverConfig:
    root: Path
    key: str
    bind_host: str = '127.0.0.1'
    port: int = 9080


def create_receiver(config: ReceiverConfig) -> Flask:
    reject_links(config.root)
    if len(config.key) < 12:
        raise ValueError('Receiver key is too short')
    config.root.mkdir(parents=True, exist_ok=True)
    lock = _locks.setdefault(str(config.root.absolute()), threading.Lock())
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = 10000000

    @app.errorhandler(HTTPException)
    def error(value):
        return jsonify(error=value.description), value.code

    @app.post('/receive')
    def receive():
        if not hmac.compare_digest(request.headers.get('X-Lab-Receiver-Key', ''), config.key):
            abort(403)
        identity = request.headers.get('X-Transfer-ID', '')
        try:
            if str(UUID(identity)) != identity:
                raise ValueError()
        except ValueError:
            abort(400)
        body = request.get_data()
        if not body:
            abort(400)
        digest = sha256(body).hexdigest()
        if digest != request.headers.get('X-Payload-SHA256'):
            abort(422)
        receipt = {'transfer_id': identity, 'received_bytes': len(body), 'sha256': digest, 'received_at': utc_now()}
        with lock:
            reject_links(config.root)
            path = config.root / f'{identity}.bin'
            reject_links(path)
            if path.exists():
                abort(409)
            if sum(item.stat().st_size for item in config.root.glob('*.bin')) + len(body) > 250000000:
                abort(507, 'Lab receiver storage budget exhausted')
            partial = config.root / f'{identity}.part'
            try:
                with partial.open('xb') as output:
                    output.write(body)
                    output.flush()
                    os.fsync(output.fileno())
                partial.rename(path)
                log = config.root / 'receiver.jsonl'
                reject_links(log)
                with log.open('a', encoding='utf-8') as output:
                    output.write(json.dumps(receipt) + '\n')
                    output.flush()
                    os.fsync(output.fileno())
            except OSError:
                abort(503, 'Receiver storage failure; reconcile any partial objects')
        return jsonify(receipt), 201

    return app
