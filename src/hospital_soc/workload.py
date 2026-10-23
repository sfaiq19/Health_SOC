"""Representative normal workflows. Ground truth remains separate from audit events."""
import json
from pathlib import Path
import random
import time

from .client import LabClient, run_context
from .config import LabConfig


def planned_operations(duration_s: int, seed: int, pause_documents=False, include_exports=False) -> list[dict]:
    if not 1 <= duration_s <= 86400:
        raise ValueError('Duration must be 1–86400 seconds')
    rng = random.Random(seed)
    result = []
    for second in range(duration_s):
        if second % 30 == 0:
            result.append({'at': second, 'kind': 'health'})
            result.extend({'at': second, 'kind': 'devices', 'device': f'device-{i:02}', 'value': rng.randint(65, 85)} for i in range(1, 11))
            if not pause_documents:
                result.append({'at': second, 'kind': 'documents', 'document': f'D{rng.randint(1, 50):03}'})
        if second % 45 == 0:
            result.append({'at': second, 'kind': 'records', 'patient': f'P{rng.randint(1, 67):04}'})
        if second % 120 == 0:
            result.append({'at': second, 'kind': 'laboratory'})
        if second % 600 == 0:
            result.append({'at': second, 'kind': 'login_typo'})
        if include_exports and second % 300 == 0:
            result.append({'at': second, 'kind': 'export'})
    return result


def run_baseline(config: LabConfig, duration_s: int, seed: int, *, base_url='http://10.77.0.1:8080',
                 output: Path, run_id=None, diagnostic=False, pause_documents=False, include_exports=False):
    operations = planned_operations(duration_s, seed, pause_documents, include_exports)
    credentials = json.loads((config.root / 'secrets.json').read_text())
    with run_context(config, 'baseline', run_id, seed, output, diagnostic) as manifest:
        client = LabClient(base_url, manifest, credentials)
        try:
            start = time.monotonic()
            for operation in operations:
                if not diagnostic:
                    time.sleep(max(0, start + operation['at'] - time.monotonic()))
                kind = operation['kind']
                if kind == 'health':
                    client.request('GET', '/health')
                elif kind == 'devices':
                    client.request('POST', f"/api/devices/{operation['device']}/telemetry", actor=operation['device'],
                                   body={'value': operation['value'], 'unit': 'synthetic'}, expected=(201,))
                elif kind == 'records':
                    client.request('GET', f"/api/records/{operation['patient']}", actor='nurse')
                elif kind == 'laboratory':
                    order = client.request('POST', '/api/lab/orders', actor='clinician',
                                           body={'patient_id': 'P0001', 'test': 'synthetic-cbc'}, expected=(201,))
                    client.request('POST', '/api/lab/results', actor='lab-service',
                                   body={'order_id': order['order_id'], 'value': 'synthetic-normal'}, expected=(201,))
                elif kind == 'documents':
                    client.request('PUT', f"/api/documents/{operation['document']}", actor='document-editor',
                                   body={'content': 'BENIGN SYNTHETIC UPDATE'.ljust(1024, '.')})
                elif kind == 'export':
                    client.request('POST', '/api/exports', actor='records-clerk',
                                   body={'destination_id': 'approved-lab', 'bytes': 250000})
                elif kind == 'login_typo':
                    client.request('POST', '/api/auth/login',
                                   body={'username': 'nurse', 'password': 'known-invalid-synthetic-value'}, expected=(401,))
            if not diagnostic:
                time.sleep(max(0, start + duration_s - time.monotonic()))
        finally:
            client.close()
    return manifest
