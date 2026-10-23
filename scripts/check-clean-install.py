"""Reproduce missing-backend failure then verify isolated installation in a fresh venv."""
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

root = Path.home() / 'HealthcareSOCLab' / 'build-check' / str(uuid4())
root.mkdir(parents=True, exist_ok=False)
venv = root / 'venv'
project = Path(__file__).resolve().parents[1]
subprocess.run([sys.executable, '-m', 'venv', str(venv)], check=True)
python = venv / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
clean_env = {key: value for key, value in os.environ.items() if key not in ['PYTHONPATH', 'PYTHONHOME']}
command = [str(python), '-m', 'pip', 'install', '--no-deps', '-e', str(project)]
old = subprocess.run(command + ['--no-build-isolation'], capture_output=True, text=True, env=clean_env)
(root / 'without-build-isolation.txt').write_text(old.stdout + old.stderr, encoding='utf-8')
new = subprocess.run(command, capture_output=True, text=True, env=clean_env)
(root / 'with-build-isolation.txt').write_text(new.stdout + new.stderr, encoding='utf-8')
result = {'evidence': str(root), 'old_install_returncode': old.returncode,
          'isolated_install_returncode': new.returncode,
          'regression_reproduced': old.returncode != 0, 'fixed_install_passed': new.returncode == 0}
(root / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, indent=2))
raise SystemExit(0 if result['regression_reproduced'] and result['fixed_install_passed'] else 2)
