import unittest
from pathlib import Path

from hospital_soc.vm_config import render_vm_config


class VMConfigTests(unittest.TestCase):
    def test_vm_keeps_planned_resources_and_isolated_single_adapter(self):
        text = render_vm_config(Path('installer.iso'), Path('hospital.vmdk'))
        self.assertIn('memsize = "8192"', text)
        self.assertIn('numvcpus = "4"', text)
        self.assertIn('ethernet0.vnet = "VMnet1"', text)
        self.assertNotIn('connectionType = "nat"', text)
        self.assertNotIn('ethernet1.present = "TRUE"', text)
        self.assertIn('isolation.tools.hgfs.disable = "TRUE"', text)

    def test_rejects_config_injection_in_paths(self):
        for path in ['bad"path.iso', 'bad\npath.iso']:
            with self.subTest(path=path), self.assertRaises(ValueError):
                render_vm_config(Path(path), Path('hospital.vmdk'))
