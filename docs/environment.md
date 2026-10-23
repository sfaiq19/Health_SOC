# Healthcare SOC environment

Status on 22 October 2026: preflight is implemented; the live lab is not provisioned or accepted.

## Host-specific evidence

`scripts/check-environment.ps1` records local operating-system, capacity, virtualization, installed-tool, privilege, and network-adapter observations. Its JSON output under `evidence/environment/` is machine-specific and ignored by Git. Keep it on the host where it was collected; do not publish raw host facts.

## Reproduce the preflight

From the project root, use Windows PowerShell:

```powershell
.\scripts\check-environment.ps1
$env:PYTHONPATH = 'src'
python -m hospital_soc.preflight evidence/environment/host-facts.json --output evidence/environment/assessment.json
python -m unittest discover -s tests -v
```

The preflight reports readiness blockers; it does not establish lab acceptance. The 10 GiB free-memory threshold is an initial allocation guard for the planned 8 GiB VM plus headroom, not a benchmark. The host must also pass the documented stability checks.

## Lab setup constraints

The planned Ubuntu Server VM uses 4 vCPUs, 8 GiB RAM, and a 60 GiB disk. Use an isolated host-only network and verify its subnet before sending lab traffic. Do not bridge measured traffic to Wi-Fi or use NAT during measured runs. Keep unrelated VMs and services unchanged.

Windows administrator access is needed only for driver, agent, and narrowly scoped firewall setup. The hospital service runs as an ordinary user. Verify dashboard access, agent identity, cross-host capture, clocks, and stability before marking the environment accepted. See [the operator handoff](operator-handoff.md) for the setup and evidence procedure.
