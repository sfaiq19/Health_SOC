from hashlib import sha256
import json
import os
from pathlib import Path
import re
import threading

from flask import Blueprint, current_app, g, jsonify, abort

from .auth import body_object, require_roles, text_field
from .config import LabConfig
from .store import validate_runtime, reject_links, document_seed

bp = Blueprint('documents', __name__)
_lock = threading.RLock()


@bp.get('/api/documents/hashes')
@require_roles('document-editor')
def inventory():
    cfg = current_app.extensions['lab']
    with _lock:
        result = {f'D{i:03}': sha256(document_path(cfg, f'D{i:03}').read_bytes()).hexdigest() for i in range(1, 51)}
    g.action = 'document_inventory'
    return jsonify(hashes=result, root=str((cfg.root / 'documents').resolve()))


def document_path(config: LabConfig, document_id: str) -> Path:
    root = validate_runtime(config)
    if not re.fullmatch(r'D\d{3}', document_id) or not 1 <= int(document_id[1:]) <= 50:
        raise ValueError('Unknown document ID')
    path = root / 'documents' / f'{document_id}.txt'
    reject_links(path)
    if not path.is_file() or not path.resolve().is_relative_to((root / 'documents').resolve()):
        raise ValueError('Document is not an existing local dummy file')
    return path


def update_document(config: LabConfig, document_id: str, content: bytes) -> dict:
    if not 1 <= len(content) <= 65536:
        raise ValueError('Document content limit exceeded')
    with _lock:
        path = document_path(config, document_id)
        before = sha256(path.read_bytes()).hexdigest()
        with path.open('wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        return {'document_id': document_id, 'path': str(path),
                'sha256_before': before, 'sha256_after': sha256(path.read_bytes()).hexdigest()}


def restore_documents(config: LabConfig, seed_manifest: dict) -> dict:
    root = validate_runtime(config)
    if (root / '.run.lock').exists() or (root / '.service.lock').exists():
        raise ValueError('Stop active runs and the service before restoring documents')
    recorded = json.loads((root / 'seed-manifest.json').read_text())
    if recorded != seed_manifest:
        raise ValueError('Restore manifest differs from the runtime seed manifest')
    paths = {identity: document_path(config, identity) for identity in recorded['documents']}
    expected = {f'D{i:03}' for i in range(1, 51)}
    if set(paths) != expected:
        raise ValueError('Incomplete document manifest')
    contents = {identity: document_seed(identity, recorded['seed']) for identity in paths}
    if any(sha256(contents[i]).hexdigest() != recorded['documents'][i] for i in paths):
        raise ValueError('Seed content does not match manifest')
    for identity in paths:
        update_document(config, identity, contents[identity])
    verified = all(sha256(path.read_bytes()).hexdigest() == recorded['documents'][identity] for identity, path in paths.items())
    return {'restored': len(paths), 'verified': verified}


@bp.put('/api/documents/<document_id>')
@require_roles('document-editor')
def put_document(document_id):
    body = body_object()
    content = text_field(body, 'content', 65536).encode('utf-8')
    try:
        document_path(current_app.extensions['lab'], document_id)
        current_app.extensions['emit']('operation_intent', 'success', 200, {'operation': 'document_update', 'document_id': document_id})
        result = update_document(current_app.extensions['lab'], document_id, content)
    except ValueError as error:
        abort(400, str(error))
    g.action = 'document_update'
    g.details.update(result)
    return jsonify(result)
