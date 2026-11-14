"""Tamper regressions for synthetic native proof fixtures."""
from hashlib import sha256
import json

import pytest

from evidence_fixtures import evidence_bundle
from hospital_soc.evaluate import evaluate_run


@pytest.mark.parametrize('mutation', [
    'old-schema', 'missing-transcript', 'wrong-hash', 'wrong-rules', 'short-gap',
    'session-change', 'reused-session', 'metadata-time', 'duplicate-id',
])
def test_native_proof_rejects_inconsistent_expiry_evidence(tmp_path, monkeypatch, mutation):
    manifest, rows = evidence_bundle(tmp_path)
    monkeypatch.setattr('hospital_soc.evaluate.verified_packet_rows', lambda *args: rows)
    proof_file = tmp_path / 'native-rule-tests.json'
    proof = json.loads(proof_file.read_text())
    case = next(c for c in proof['cases'] if c['case'] == 'auth-expiry')
    path = tmp_path / 'auth-expiry.txt'
    text = path.read_text()
    if mutation == 'old-schema':
        proof['validation_schema'] = 2
    elif mutation == 'missing-transcript':
        path.unlink()
    elif mutation == 'wrong-hash':
        case['transcript_sha256'] = '0' * 64
    elif mutation == 'wrong-rules':
        text = text.replace("id: '110001'", "id: '110101'", 1)
    elif mutation == 'short-gap':
        text = text.replace('00:01:05', '00:00:59')
        case['engine_times'][-1] = case['engine_times'][-1].replace('00:01:05', '00:00:59')
    elif mutation == 'session-change':
        text = text.replace('synthetic-auth-expiry', 'replaced-session', 1)
    elif mutation == 'reused-session':
        other = next(c for c in proof['cases'] if c['case'] == 'reads-expiry')
        other['session_sha256'] = case['session_sha256']
    elif mutation == 'metadata-time':
        case['engine_times'][-1] = case['engine_times'][0]
    elif mutation == 'duplicate-id':
        text = text.replace(case['event_ids'][-1], case['event_ids'][0])
        case['event_ids'][-1] = case['event_ids'][0]
    if mutation in {'wrong-rules', 'short-gap', 'session-change', 'duplicate-id'}:
        raw = text.encode()
        path.write_bytes(raw)
        case['transcript_sha256'] = sha256(raw).hexdigest()
    proof_file.write_text(json.dumps(proof))
    result = evaluate_run(manifest, tmp_path)
    assert result['status'] != 'complete', result
    assert any('Native' in issue for issue in result['issues'])
