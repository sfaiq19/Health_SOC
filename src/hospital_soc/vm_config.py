"""Configuration for the dedicated powered-off VMware lab guest."""
from pathlib import Path


def render_vm_config(iso: Path, disk: Path) -> str:
    paths = [str(path.resolve()) for path in (iso, disk)]
    if any(any(char in path for char in ['"', '\n', '\r', '\0']) for path in paths):
        raise ValueError('Invalid VMware path')
    settings = {
        '.encoding': 'UTF-8', 'config.version': '8', 'virtualHW.version': '20',
        'displayName': 'Healthcare SOC Ubuntu 24.04', 'guestOS': 'ubuntu-64',
        'firmware': 'efi', 'memsize': '8192', 'numvcpus': '4',
        'cpuid.coresPerSocket': '4', 'scsi0.present': 'TRUE',
        'scsi0.virtualDev': 'lsisas1068', 'scsi0:0.present': 'TRUE',
        'scsi0:0.fileName': paths[1], 'sata0.present': 'TRUE',
        'sata0:0.present': 'TRUE', 'sata0:0.deviceType': 'cdrom-image',
        'sata0:0.fileName': paths[0], 'sata0:0.startConnected': 'TRUE',
        'ethernet0.present': 'TRUE', 'ethernet0.connectionType': 'custom',
        'ethernet0.vnet': 'VMnet1', 'ethernet0.virtualDev': 'vmxnet3',
        'ethernet0.addressType': 'generated', 'ethernet0.startConnected': 'TRUE',
        'ethernet1.present': 'FALSE', 'usb.present': 'FALSE', 'sound.present': 'FALSE',
        'sharedFolder.maxNum': '0', 'isolation.tools.hgfs.disable': 'TRUE',
        'isolation.tools.copy.disable': 'TRUE', 'isolation.tools.paste.disable': 'TRUE',
        'tools.syncTime': 'TRUE', 'bios.bootDelay': '3000',
    }
    return ''.join(f'{key} = "{value}"\n' for key, value in settings.items())
