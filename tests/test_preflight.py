import copy
import unittest

from hospital_soc.preflight import assess_environment


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.facts = {
            'free_ram_gib': 10, 'free_disk_gib': 100, 'logical_processors': 8,
            'administrator': True, 'hypervisor_present': True,
            'virtualization_firmware_enabled': False, 'vmware_installed': True,
            'wazuh_agent_installed': True, 'capture_installed': True,
            'lab_vm_running': True, 'lab_network_verified': True,
        }

    def test_low_memory_is_blocked_without_reducing_vm_allocation(self):
        self.facts['free_ram_gib'] = 3.3
        result = assess_environment(self.facts)
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('insufficient_free_ram', result['blockers'])
        self.assertEqual(result['vm_ram_gib'], 8)

    def test_hypervisor_present_does_not_mean_firmware_virtualization_disabled(self):
        self.assertEqual(assess_environment(self.facts)['status'], 'ready_for_smoke_tests')

    def test_unknown_or_unavailable_virtualization_blocks_setup(self):
        self.facts['hypervisor_present'] = False
        self.facts['virtualization_firmware_enabled'] = False
        self.assertIn('virtualization_unavailable_or_unknown', assess_environment(self.facts)['blockers'])

    def test_missing_observations_are_unknown_and_block_readiness(self):
        del self.facts['lab_network_verified']
        result = assess_environment(self.facts)
        self.assertEqual(result['status'], 'blocked')
        self.assertIn('unknown_lab_network_verified', result['blockers'])

    def test_admin_and_actual_vm_and_telemetry_are_required(self):
        for key in ['administrator', 'lab_vm_running', 'wazuh_agent_installed', 'capture_installed']:
            with self.subTest(key=key):
                facts = copy.deepcopy(self.facts)
                facts[key] = False
                self.assertEqual(assess_environment(facts)['status'], 'blocked')

    def test_preflight_ready_does_not_claim_live_acceptance(self):
        result = assess_environment(self.facts)
        self.assertEqual(result['status'], 'ready_for_smoke_tests')
        self.assertFalse(result['task_1_accepted'])


if __name__ == '__main__':
    unittest.main()
