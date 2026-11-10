# Healthcare SOC environment

Status on 10 November 2026: Preflight re-executed, Ubuntu 24.04.5 ISO fully downloaded and verified against official SHA-256 sums, Windows hospital runtime seeded (seed 101), rendered agent XML snippets staged, and private guest handoff archive prepared. The live guest VM is not booted or accepted; host resource blockers and privilege gates remain explicitly recorded.

## 10 November 2026 preflight readings

Re-executed on Windows host via `.\scripts\check-environment.ps1` and evaluated with `hospital_soc.preflight`:

- **Operating System:** Microsoft Windows 11 Home
- **Host CPU / Topology:** 14 logical processors
- **Host RAM:** 15.45 GiB total, 3.05 GiB free (threshold 10.00 GiB for 8 GiB VM + 2 GiB headroom; blocker `insufficient_free_ram`)
- **Host Storage:** 265.28 GiB available free space on volume `C:` (satisfies 60 GiB disk requirement)
- **Privilege:** Administrator = `false` (blocker `missing_administrator`)
- **Virtualization & Hypervisor:** `hypervisor_present = true`, `virtualization_firmware_enabled = false` (firmware virtualization may be masked by active hypervisor)
- **VMware Workstation Version:** `26.0.0 build-25388281` (`C:\Program Files\VMware\VMware Workstation\vmware.exe` / `vmrun.exe`)
- **Running VMs:** 0 (`Total running VMs: 0`)
- **Active IPv4 Interfaces:** Existing host adapter addresses are retained only in the ignored local preflight evidence. Configure the dedicated lab network on `10.77.0.0/24` after verifying the actual adapter and routes.
- **Subnet Collision Check (`10.77.0.0/24`):**
  - Evaluated via `Get-NetIPAddress -AddressFamily IPv4` and `Get-NetRoute -AddressFamily IPv4`.
  - Zero matching addresses and zero routes exist in `10.77.*`. No collision detected.
- **Readiness Assessment (`evidence/environment/assessment.json`):**
  - Status: `blocked` (`task_1_accepted: false`)
  - Active blockers: `insufficient_free_ram`, `missing_administrator`, `missing_wazuh_agent_installed`, `unknown_lab_vm_running`, `unknown_lab_network_verified`.

## Ubuntu 24.04.5 ISO verification

The operating system installer retrieval completed and verified via `scripts/download-ubuntu.py`:
- **Source:** `https://releases.ubuntu.com/24.04/ubuntu-24.04.5-live-server-amd64.iso`
- **Verification Source:** `https://releases.ubuntu.com/24.04/SHA256SUMS`
- **File Path:** `$env:USERPROFILE\HealthcareSOCLab\installers\ubuntu-24.04.5-live-server-amd64.iso`
- **Receipt Path:** `$env:USERPROFILE\HealthcareSOCLab\installers\ubuntu-verification.json`
- **Size:** 4,080,486,400 bytes (3,891.46 MiB)
- **SHA-256:** `97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8` (exact match against Ubuntu official checksum)

## Windows hospital runtime & private handoff preparation

The offline Windows preparation steps for Task 2 have been executed:
- **Runtime Root:** `$env:USERPROFILE\HealthcareSOCLab\hospital`
- **Database:** `hospital.sqlite` seeded with `--seed 101` containing 200 synthetic patients and 10 device identities.
- **Documents:** 50 baseline dummy files (`documents\D001.txt` through `documents\D050.txt`).
- **Secrets & Manifest:** `secrets.json` and `seed-manifest.json` generated.
- **Local Config:** `config\lab.local.json` created from `config\lab.example.json` with resolved `runtime_root` (git-ignored).
- **Rendered Agent XML:**
  - `$env:USERPROFILE\HealthcareSOCLab\hospital\agent-localfile.rendered.xml` (points to `$env:USERPROFILE\HealthcareSOCLab\hospital\logs\app.jsonl`)
  - `$env:USERPROFILE\HealthcareSOCLab\hospital\agent-fim.rendered.xml` (monitors `$env:USERPROFILE\HealthcareSOCLab\hospital\documents`)
- **Private Guest Handoff Archive:** `$env:USERPROFILE\HealthcareSOCLab\hospital\private-handoff.zip` (121,093 bytes, mode 0600) built with `scripts\prepare-handoff.py`, containing the complete A1–A4 hardened application tree, client configuration, and lab credentials ready for transfer to the guest VM.

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
