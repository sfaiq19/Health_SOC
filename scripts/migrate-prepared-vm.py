"""Copy this project's powered-off VM out of packaged-AppData redirection. Never deletes source."""
import json
import os
from pathlib import Path
import shutil
import subprocess

from hospital_soc.vm_config import render_vm_config

source = (Path(os.environ['LOCALAPPDATA']) / 'HealthcareSOCLab').resolve()
destination = (Path.home() / 'HealthcareSOCLab').resolve()
if destination.exists():
    raise SystemExit('Destination already exists; refusing to merge or overwrite runtime data.')
vmrun = Path('C:/Program Files/VMware/VMware Workstation/vmrun.exe')
inventory = subprocess.run([str(vmrun), 'list'], check=True, capture_output=True, text=True).stdout
if 'Total running VMs: 0' not in inventory:
    raise SystemExit('Power off guests before preparing this copy.')
if not (source / 'vm/Healthcare-SOC.vmx').is_file():
    raise SystemExit('Expected source VM not found')
destination.mkdir()
shutil.copytree(source / 'vm', destination / 'vm')
(destination / 'installers').mkdir()
for name in ['SHA256SUMS', 'ubuntu-24.04.5-live-server-amd64.iso.part',
             'ubuntu-24.04.5-live-server-amd64.iso', 'ubuntu-verification.json']:
    path = source / 'installers' / name
    if path.is_file():
        shutil.copyfile(path, destination / 'installers' / name)
vmx = destination / 'vm/Healthcare-SOC.vmx'
disk = destination / 'vm/healthcare-soc.vmdk'
iso = destination / 'installers/ubuntu-24.04.5-live-server-amd64.iso'
vmx.write_text(render_vm_config(iso, disk), encoding='utf-8')
receipt = {'source_preserved': str(source), 'runtime_parent': str(destination), 'vmx': str(vmx),
           'disk': str(disk), 'installer': str(iso), 'ram_mib': 8192, 'vcpus': 4, 'disk_gb': 60,
           'powered_on': False, 'os_installed': False, 'installer_verified': False}
(destination / 'vm/preparation.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
print(json.dumps(receipt, indent=2))
