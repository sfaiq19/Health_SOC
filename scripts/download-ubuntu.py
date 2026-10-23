"""Download the selected Ubuntu server ISO, publishing it only after SHA-256 verification."""
import hashlib
import json
import os
from pathlib import Path
import time
import urllib.request

from hospital_soc.download import fetch_verified

name = 'ubuntu-24.04.5-live-server-amd64.iso'
base = 'https://releases.ubuntu.com/24.04/'
root = Path.home() / 'HealthcareSOCLab' / 'installers'
root.mkdir(parents=True, exist_ok=True)
root = root.resolve()
destination = root / name
with urllib.request.urlopen(base + 'SHA256SUMS', timeout=60) as response:
    sums = response.read().decode('utf-8')
expected = [line.split()[0] for line in sums.splitlines() if line.split()[-1].lstrip('*') == name]
if len(expected) != 1 or len(expected[0]) != 64:
    raise SystemExit('ISO checksum is absent or ambiguous; refusing download.')
(root / 'SHA256SUMS').write_text(sums, encoding='utf-8')

fetch_verified(base + name, destination, expected[0],
               progress=lambda received, total: print(f'Downloaded {received / 1024**2:.0f}/{total / 1024**2:.0f} MiB', flush=True))
receipt = {'source': base + name, 'sha256': expected[0], 'bytes': destination.stat().st_size,
           'path': str(destination), 'verified_against': base + 'SHA256SUMS',
           'note': 'Checksums fetched over HTTPS; GPG signature verification is not claimed.'}
(root / 'ubuntu-verification.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
print(json.dumps(receipt), flush=True)
