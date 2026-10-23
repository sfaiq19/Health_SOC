"""Create a fresh sparse 60 GB VMware disk and VMX. Never powers on or alters existing VMs."""
import json
import os
from pathlib import Path
import subprocess

from hospital_soc.vm_config import render_vm_config

root = (Path.home() / 'HealthcareSOCLab').resolve()
folder = root / 'vm'
folder.mkdir(parents=True, exist_ok=False)
manager = Path('C:/Program Files/VMware/VMware Workstation/vmware-vdiskmanager.exe')
if not manager.is_file():
    raise SystemExit('VMware disk manager unavailable at verified installation path.')
disk = folder / 'healthcare-soc.vmdk'
iso = root / 'installers/ubuntu-24.04.5-live-server-amd64.iso'
subprocess.run([str(manager), '-c', '-s', '60GB', '-a', 'lsilogic', '-t', '1', str(disk)], check=True)
if not disk.is_file():
    raise SystemExit('Disk creation returned without a disk descriptor.')
vmx = folder / 'Healthcare-SOC.vmx'
vmx.write_text(render_vm_config(iso, disk), encoding='utf-8')
receipt = {'vmx': str(vmx), 'disk': str(disk), 'installer': str(iso),
           'ram_mib': 8192, 'vcpus': 4, 'disk_gb': 60, 'network': 'VMnet1',
           'powered_on': False, 'os_installed': False, 'installer_verified': False,
           'note': 'Check ubuntu-verification.json and current memory before first boot. VMnet1 isolation remains unverified.'}
(folder / 'preparation.json').write_text(json.dumps(receipt, indent=2), encoding='utf-8')
print(json.dumps(receipt, indent=2))
