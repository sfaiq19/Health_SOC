from hashlib import sha256
from io import BytesIO
import re

import pytest

from hospital_soc.download import fetch_verified


def server_for(payload):
    def open_range(request, timeout):
        start, end = map(int, re.search(r'bytes=(\d+)-(\d+)', request.headers['Range']).groups())
        end = min(end, len(payload) - 1)
        response = BytesIO(payload[start:end + 1])
        response.status = 206
        response.headers = {'Content-Range': f'bytes {start}-{end}/{len(payload)}'}
        return response
    return open_range


def test_download_resumes_and_verifies_before_publishing(tmp_path):
    payload = b'0123456789abcdef'
    destination = tmp_path / 'image.iso'
    destination.with_suffix('.iso.part').write_bytes(payload[:3])
    fetch_verified('https://example.test/image.iso', destination, sha256(payload).hexdigest(),
                   opener=server_for(payload), chunk_bytes=4)
    assert destination.read_bytes() == payload
    assert not destination.with_suffix('.iso.part').exists()


def test_wrong_digest_never_publishes_partial_image(tmp_path):
    destination = tmp_path / 'image.iso'
    with pytest.raises(ValueError):
        fetch_verified('https://example.test/image.iso', destination, '0' * 64,
                       opener=server_for(b'payload'), chunk_bytes=4)
    assert not destination.exists()
    assert destination.with_suffix('.iso.part').exists()


def test_range_response_must_match_requested_offset(tmp_path):
    destination = tmp_path / 'image.iso'
    destination.with_suffix('.iso.part').write_bytes(b'abc')
    with pytest.raises(ValueError):
        fetch_verified('https://example.test/image.iso', destination, '0' * 64,
                       opener=server_for(b'ab'), chunk_bytes=4)
    assert not destination.exists()
