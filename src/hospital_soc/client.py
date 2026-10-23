"""Bounded lab HTTP client and ground-truth receipts; never emits detector decisions."""
from contextlib import contextmanager
from dataclasses import asdict
import json
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4, UUID

import requests

from .audit import utc_now
from .contracts import RunManifest


class OperationFailed(RuntimeError):
    pass


def save_manifest(manifest: RunManifest, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    path = output / 'manifest.json'
    temporary = output / 'manifest.json.tmp'
    temporary.write_text(json.dumps(asdict(manifest), indent=2), encoding='utf-8')
    temporary.replace(path)


class LabClient:
    def __init__(self, base_url: str, manifest: RunManifest, credentials: dict):
        url = urlparse(base_url)
        if url.scheme != 'http' or url.hostname not in {'127.0.0.1', '10.77.0.1'} or url.username or url.password or url.path not in {'', '/'}:
            raise ValueError('Use the registered hospital lab URL only')
        if not url.port or not 1024 <= url.port <= 65535:
            raise ValueError('Invalid lab port')
        self.base_url, self.manifest, self.credentials = base_url.rstrip('/'), manifest, credentials
        self.session = requests.Session()
        self.session.trust_env = False
        self.tokens = {}

    def close(self):
        self.session.close()

    def request(self, method, path, *, actor=None, body=None, expected=(200,), token=None):
        if not path.startswith(('/api/', '/health')) or '?' in path or '://' in path or '..' in path:
            raise ValueError('Invalid lab route')
        request_id = str(uuid4())
        headers = {'X-Lab-Run-ID': self.manifest.run_id, 'X-Request-ID': request_id}
        if actor and token is None:
            token = self.token(actor)
        if token:
            headers['Authorization'] = 'Bearer ' + token
        receipt = {'request_id': request_id, 'method': method, 'path': path,
                   'actor': actor or 'anonymous', 'started_at': utc_now()}
        try:
            response = self.session.request(method, self.base_url + path, headers=headers,
                                           json=body, timeout=(3, 15), allow_redirects=False)
            receipt.update(status=response.status_code, ended_at=utc_now(),
                           response_request_id=response.headers.get('X-Request-ID'))
            self.manifest.receipts.append(receipt)
            if response.status_code not in expected or receipt['response_request_id'] != request_id:
                raise OperationFailed(f'Unexpected response to {method} {path}: {response.status_code}')
            data = response.json()
            receipt['result'] = {key: data[key] for key in ['order_id', 'result_id', 'document_id',
                                  'sha256_before', 'sha256_after', 'bytes_sent', 'payload_sha256', 'transfer_id'] if key in data}
            return data
        except requests.RequestException as error:
            receipt.update(status=None, ended_at=utc_now(), error=type(error).__name__)
            if receipt not in self.manifest.receipts:
                self.manifest.receipts.append(receipt)
            raise OperationFailed(f'Lab HTTP operation failed: {type(error).__name__}') from error

    def token(self, actor):
        if actor in self.credentials['devices']:
            return self.credentials['devices'][actor]
        if actor not in self.tokens:
            response = self.request('POST', '/api/auth/login', body={
                'username': actor, 'password': self.credentials['passwords'][actor]})
            self.tokens[actor] = response['token']
        return self.tokens[actor]


@contextmanager
def run_context(config, scenario, run_id, seed, output, diagnostic):
    identity = run_id or str(uuid4())
    if str(UUID(identity)) != identity:
        raise ValueError('Use an opaque canonical UUID run ID')
    if output.exists() and any(output.iterdir()):
        raise ValueError('Use a new run directory; do not overwrite evidence')
    for watched in [config.root / 'logs', config.root / 'documents']:
        if output.resolve().is_relative_to(watched.resolve()):
            raise ValueError('Ground truth cannot be stored in monitored paths')
    manifest = RunManifest(identity, scenario, seed, config.policy_mode, utc_now())
    if diagnostic:
        manifest.notes.append('Diagnostic timing: sleeps skipped; not a measured acceptance run.')
    save_manifest(manifest, output)
    try:
        yield manifest
        manifest.status = 'generated'
    except (OperationFailed, OSError, ValueError, KeyError) as error:
        manifest.status = 'invalid'
        manifest.notes.append(str(error))
    finally:
        manifest.ended_at = utc_now()
        save_manifest(manifest, output)
