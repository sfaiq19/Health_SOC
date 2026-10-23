"""Resumable, range-checked retrieval with publication only after digest verification."""
from hashlib import file_digest
from pathlib import Path
import re
import time
import urllib.error
import urllib.request


def digest(path):
    with path.open('rb') as stream:
        return file_digest(stream, 'sha256').hexdigest()


def fetch_verified(url: str, destination: Path, expected: str, *, opener=urllib.request.urlopen,
                   chunk_bytes=64 * 1024 * 1024, progress=None):
    if not re.fullmatch('[0-9a-f]{64}', expected) or chunk_bytes < 1:
        raise ValueError('Invalid checksum or chunk size')
    if destination.exists():
        if digest(destination) != expected:
            raise ValueError('Existing installer differs; refusing to overwrite')
        return
    partial = destination.with_name(destination.name + '.part')
    destination.parent.mkdir(parents=True, exist_ok=True)
    total = None
    errors = 0
    while total is None or partial.stat().st_size < total:
        offset = partial.stat().st_size if partial.exists() else 0
        end = offset + chunk_bytes - 1
        request = urllib.request.Request(url, headers={'Range': f'bytes={offset}-{end}'})
        try:
            with opener(request, timeout=60) as response:
                match = re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)', response.headers.get('Content-Range', ''))
                if response.status != 206 or not match:
                    raise ValueError('Server did not honor the bounded range request')
                first, last, size = map(int, match.groups())
                if first != offset or last < first or last > end or size <= last or total not in (None, size):
                    raise ValueError('Range response contradicts the requested offset or file length')
                total = size
                remaining = last - first + 1
                with partial.open('ab') as output:
                    while remaining:
                        chunk = response.read(min(4 * 1024 * 1024, remaining))
                        if not chunk:
                            raise OSError('Interrupted installer chunk')
                        output.write(chunk)
                        remaining -= len(chunk)
            errors = 0
            if progress:
                progress(partial.stat().st_size, total)
        except (OSError, urllib.error.URLError):
            errors += 1
            if errors >= 3:
                raise
            time.sleep(errors * 2)
    if digest(partial) != expected:
        raise ValueError('SHA-256 mismatch; partial image retained, not published')
    partial.rename(destination)
