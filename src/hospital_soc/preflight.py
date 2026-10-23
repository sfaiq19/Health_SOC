"""Conservative assessment of observed host facts, without installing anything."""

import argparse
import json
import math
from pathlib import Path


def assess_environment(facts: dict) -> dict:
    blockers = []
    for name, minimum in [('free_ram_gib', 10), ('free_disk_gib', 70), ('logical_processors', 4)]:
        value = facts.get(name)
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or value < 0:
            blockers.append('unknown_' + name)
        elif value < minimum:
            blockers.append('insufficient_' + name.removesuffix('_gib'))
    for name in ['administrator', 'vmware_installed', 'wazuh_agent_installed',
                 'capture_installed', 'lab_vm_running', 'lab_network_verified']:
        value = facts.get(name)
        if type(value) is not bool:
            blockers.append('unknown_' + name)
        elif not value:
            blockers.append('missing_' + name)
    if facts.get('hypervisor_present') is not True and facts.get('virtualization_firmware_enabled') is not True:
        blockers.append('virtualization_unavailable_or_unknown')
    return {
        'status': 'blocked' if blockers else 'ready_for_smoke_tests',
        'blockers': blockers, 'vm_ram_gib': 8,
        'task_1_accepted': False,
        'note': 'Readiness is not acceptance: dashboard/agent/capture/clock and stability smoke tests are separate.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('facts', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    facts = json.loads(args.facts.read_text(encoding='utf-8-sig'))
    result = assess_environment(facts)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 2 if result['blockers'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
