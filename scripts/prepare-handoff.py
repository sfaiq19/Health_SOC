"""Build a private VM handoff archive excluding virtualenv, Git and public evidence."""
import argparse
import json
import os
from pathlib import Path
import zipfile

from hospital_soc.config import LabConfig
from hospital_soc.store import validate_runtime

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--runtime', type=Path, required=True)
parser.add_argument('--guest-user', default='labuser')
args = parser.parse_args()
if args.guest_user != 'labuser':
    raise SystemExit('This handoff layout expects the documented labuser guest account.')
cfg = LabConfig(root=args.runtime)
validate_runtime(cfg)
project = Path(__file__).resolve().parents[1]
destination = cfg.root / 'private-handoff.zip'
if destination.exists():
    raise SystemExit('Preserve the old private handoff and use an explicit new runtime if rebuilding.')
guest_root = '/home/labuser/healthcare-soc-runtime'
configuration = json.loads((project / 'config/lab.example.json').read_text())
configuration['runtime_root'] = guest_root
with zipfile.ZipFile(destination, 'x', zipfile.ZIP_DEFLATED) as archive:
    for folder in ['src', 'scripts', 'siem', 'config', 'docs']:
        for path in (project / folder).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts and '.egg-info' not in str(path) and '.local.' not in path.name:
                archive.write(path, str(Path('project') / path.relative_to(project)))
    for name in ['pyproject.toml', 'requirements-lock.txt', 'README.md']:
        archive.write(project / name, f'project/{name}')
    archive.writestr('project/config/client.local.json', json.dumps(configuration, indent=2))
    archive.write(cfg.root / 'secrets.json', 'runtime/secrets.json')
os.chmod(destination, 0o600)
print(json.dumps({'private_archive': str(destination), 'warning': 'Contains disposable lab credentials. Copy only to the isolated VM; do not upload publicly.'}))
