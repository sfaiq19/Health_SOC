"""Three bounded client sequences using ordinary hospital routes."""
import json
from pathlib import Path
import time

from .__main__ import runtime_lock
from .client import LabClient, OperationFailed, run_context
from .config import LabConfig


def run_scenario(config: LabConfig, scenario: str, run_id=None, seed=201, *, output: Path,
                 base_url='http://10.77.0.1:8080', diagnostic=False):
    if scenario not in {'s1', 's2', 's3'}:
        raise ValueError('Unknown scenario')
    credentials = json.loads((config.root / 'secrets.json').read_text())
    with runtime_lock(config.root, '.run.lock'), run_context(config, scenario, run_id, seed, output, diagnostic) as manifest:
        client = LabClient(base_url, manifest, credentials)
        wait = (lambda seconds: None) if diagnostic else time.sleep
        try:
            health = client.request('GET', '/health')
            effective_policy = health.get('policy_mode')
            if effective_policy not in {'observe', 'enforce'}:
                raise OperationFailed('Server did not report an explicit policy mode')
            manifest.policy_mode = effective_policy
            if scenario == 's1':
                for _ in range(6):
                    client.request('POST', '/api/auth/login', body={'username': 'clinician', 'password': 'known-invalid-synthetic-value'}, expected=(401,))
                    wait(5)
                for number in range(100, 130):
                    client.request('GET', f'/api/records/P{number:04}', actor='clinician',
                                   expected=(403,) if effective_policy == 'enforce' else (200,))
                    wait(1.5)
            elif scenario == 's2':
                inventory = client.request('GET', '/api/documents/hashes', actor='document-editor')
                before = inventory['hashes']
                manifest.metadata['document_root'] = inventory['root']
                if len(before) != 50:
                    raise OperationFailed('Incomplete initial document inventory')
                (output / 'file-hashes-before.json').write_text(json.dumps(before, indent=2))
                for number in range(1, 51):
                    identity = f'D{number:03}'
                    content = f'SYNTHETIC MARKER {identity} seed={seed}'.ljust(1024, 'Z')
                    client.request('PUT', f'/api/documents/{identity}', actor='document-editor', body={'content': content})
                    wait(1)
                after = client.request('GET', '/api/documents/hashes', actor='document-editor')['hashes']
                (output / 'file-hashes-after.json').write_text(json.dumps(after, indent=2))
                if set(before) != set(after) or any(before[x] == after[x] for x in before):
                    raise OperationFailed('Not all 50 document hashes changed')
                manifest.notes.append('Filesystem hashes read through separate inventory requests. Native FIM corroboration remains required.')
            else:
                client.request('POST', '/api/exports', actor='records-clerk',
                               body={'destination_id': 'unapproved-lab', 'bytes': 5000000},
                               expected=(403,) if effective_policy == 'enforce' else (200,))
        finally:
            client.close()
    return manifest
