# Healthcare SOC VM guide for my phone

**13 November update.** Ubuntu and Wazuh 4.14.10 are installed on VMnet4 with guest ens192=10.77.0.10. The three diagnostic scenarios ran successfully. Resume with the [current revalidation procedure](2026-11-13-native-revalidation.md) and [acceptance ledger](implementation-progress.md). The installation walkthrough below is historical rebuild guidance.

## Paste this into a new ChatGPT conversation and attach this guide

“Be my hands-on tutor for the Healthcare SOC lab described in the attached guide. I am using ChatGPT on my phone and doing the work myself on a Windows laptop. You cannot see my laptop or repository. Start by asking which checkpoint I last completed; if this is my first session, start at 1. Give me **one action at a time**. Say exactly where to do it (Windows PowerShell, Administrator PowerShell, VMware GUI, or Ubuntu terminal), what to click or type, what success looks like, and which short output to send you. Wait for my result before continuing. If a screen differs, ask what options I see. If something fails, troubleshoot from the actual error. Before formatting a disk or changing network settings, help me identify the exact lab target. Never ask me to send passwords, tokens, private archives or raw packet captures. At the end of a session, give me a short resume note with the last verified checkpoint, any blocker, and the next action. My first goal is simply to boot Ubuntu and successfully SSH into it from Windows.”

**How to use this from the phone.** Copy this guide to your phone or attach this Markdown file to a new chat on the laptop, then open that same conversation on your phone. Confirm the guide is visible there before closing Codex and Antigravity. Only this guide is needed for the first session. Larger command blocks below are references for the tutor to present one step at a time. After SSH works, you can type Ubuntu commands in the Windows SSH terminal instead of typing inside the VMware console.

## What is already prepared

- Host: Windows 11 Home, VMware Workstation, about 15.45 GiB total RAM. On 10 November the recorded free RAM was 3.05 GiB while other software was open. Recheck after closing the IDEs.
- Project: `C:\Users\YOUR_USERNAME\OneDrive\Desktop\SOC Project`. Private lab files: `C:\Users\YOUR_USERNAME\HealthcareSOCLab`. In Windows commands below, `$lab` means `"$env:USERPROFILE\HealthcareSOCLab"`. Set it again in each new PowerShell window.
- Existing VM: `%USERPROFILE%\HealthcareSOCLab\vm\Healthcare-SOC.vmx`, 4 virtual CPUs, 8192 MiB RAM, one 60 GiB virtual disk. Its CD already points to the verified Ubuntu Server 24.04.5 ISO in the sibling `installers` folder. Its first adapter currently points at VMnet1, previously used for another subnet.
- Windows runs the synthetic hospital API on **10.77.0.1:8080**. Ubuntu will be **10.77.0.10/24**, running Wazuh 4.14.x, traffic clients, receivers on 9080/9081, and packet capture. Your phone only provides instructions. Use the laptop to open the dashboard.
- The hospital is already seeded with 200 fictional patients, 10 devices and 50 dummy documents. The Windows runtime contains rendered agent XML snippets and a private handoff ZIP. Leave the existing seed and files in place.
- The last checked project revision was `3e764e8`. The evaluator still accepted an alert on the wrong kind of event and a lab result predating the order response, and crashed on a malformed document ID. You can do the VM work and collect native evidence now. Final acceptance requires the repaired evaluator and a matching updated guest copy. Keep the separate fixes with the coding agent.

## Session 1 — Install Ubuntu and reach it from Windows

### 1. Free memory and check the prepared files (Windows)

Save work, close Codex, Antigravity and other heavy applications you choose to close. Open Task Manager → Performance → Memory and check **Available**. The project's startup target is 10 GiB available for an 8 GiB VM. If well below target, inspect the apps consuming memory, or restart Windows and recheck before launching other apps. If the laptop cannot sustain the VM, record available RAM and stop at this checkpoint.

Open ordinary Windows PowerShell:

```powershell
$lab = "$env:USERPROFILE\HealthcareSOCLab"
Test-Path "$lab\vm\Healthcare-SOC.vmx"
Test-Path "$lab\installers\ubuntu-24.04.5-live-server-amd64.iso"
Test-Path "$lab\hospital\private-handoff.zip"
```

Expect three `True` values. The ISO was independently rehashed at 4,080,486,400 bytes with SHA-256 `97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8`. A missing path is a reason to inspect the folder before downloading or creating anything.

### 2. Create the isolated VMware network (VMware GUI and Windows)

1. Open VMware Workstation → **Edit → Virtual Network Editor**. Choose **Change Settings** if offered and approve the Windows administrator prompt. First inspect the existing list. Previously VMnet1, 2, 3 and 8 were in use.
2. If there is already a dedicated lab network on 10.77.0.0/24, verify and reuse it. Otherwise choose **Add Network**, pick an unused VMnet number and write it down. Choose **Host-only**, enable the host virtual adapter, disable VMware DHCP for this dedicated network, and set subnet `10.77.0.0`, mask `255.255.255.0`. Apply. Leave the existing networks as they are.
3. In Windows PowerShell run `Get-NetIPAddress -AddressFamily IPv4 | Format-Table InterfaceAlias,IPAddress,PrefixLength`. Find the **new VMware adapter**. Expected address is **10.77.0.1**, prefix **24**. If missing, use Windows network adapter properties (`ncpa.cpl`) → the exact new VMware adapter → IPv4 properties. Set that address and mask, leave gateway/DNS empty, then recheck. If a different adapter already owns that range, stop and identify the conflict.

### 3. Attach the VM and run the installer (VMware GUI)

1. **File → Open** the existing `Healthcare-SOC.vmx`. Before powering on, open its settings. Confirm 8 GiB, 4 vCPUs, the single lab virtual disk, and the Ubuntu ISO with CD connected at power-on.
2. For its first Network Adapter, select **Custom: Specific virtual network** and choose the dedicated VMnet from step 2. Select **Connect at power on**. This first NIC remains the lab NIC.
3. If you will download packages during setup, add a **second** network adapter set to **NAT** temporarily. Keep track of the NICs, using the MAC addresses shown in VMware's adapter settings to identify them in Ubuntu. Only the NAT NIC gets a default route. Disconnect it after all downloads, before collecting lab traffic. For an offline OS install you may defer adding it until Session 2.
4. Power on and select the Ubuntu Server installer. Choose language and keyboard. At networking, select the **lab NIC** → IPv4 → manual. If asked for *Subnet*, enter **10.77.0.0/24**; for *Address*, **10.77.0.10**. Leave gateway, nameserver and search domains blank on this NIC. Leave the temporary NAT NIC on DHCP. If an offline mirror check fails, use the installer’s offline/continue option where offered.
5. At storage, verify the target shown is the single **approximately 60 GiB VMware virtual disk**. Only then use guided whole-disk installation on that disk. If extra disks or an unexpected size appear, stop at this screen.
6. Create username **labuser**, use a private disposable password, choose **Install OpenSSH server**, and enable the login method you will use from Windows. Finish installation, reboot and disconnect the ISO if prompted. If you see the installer again, disconnect the virtual CD and boot the existing disk.
7. Log in at the VMware console and run:

```bash
grep PRETTY_NAME /etc/os-release
ip -br -4 addr
ip route
systemctl is-active ssh
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

Expect Ubuntu 24.04.x, a lab interface with `10.77.0.10/24`, and active SSH. Record the lab interface name and the **public** fingerprint. If the address is wrong, use the console to inspect `sudo netplan get` and the VMnet/MAC mapping. Have the tutor tailor the change to the actual interface and existing configuration, then use `sudo netplan try` from the console. [Ubuntu networking documentation](https://ubuntu.com/server/docs/explanation/networking/configuring-networks/)

### 4. Verify SSH (ordinary Windows PowerShell)

```powershell
Test-NetConnection 10.77.0.10 -Port 22
ssh labuser@10.77.0.10
```

Expect `TcpTestSucceeded : True`. On first connect compare the offered key fingerprint to the corresponding guest public key before accepting. Type the private guest password locally if prompted. At the Ubuntu shell run `whoami` and `hostname`. Save the two IPs, VMnet number, guest interface name and successful SSH test. **You can stop here for the day.** To shut down cleanly, run `sudo poweroff` in Ubuntu and wait for VMware to show powered off.

## Session 2 — Install guest tools and Wazuh

### 5. Transfer the prepared project on the private link

Start the VM if needed. In **ordinary Windows PowerShell**, switch to the project and copy the existing archive:

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Desktop\SOC Project"
.\scripts\copy-handoff.ps1
```

If script execution is restricted, its underlying transfer is `scp "$env:USERPROFILE\HealthcareSOCLab\hospital\private-handoff.zip" labuser@10.77.0.10:/home/labuser/healthcare-soc-handoff.zip`. The ZIP contains credentials and goes directly to the guest. Never attach it to the phone chat.

In **Ubuntu as labuser**, confirm temporary NAT connectivity and DNS, then install the tools. The following extraction sequence is for a first install with new destination directories. On resumption, check existing directories and continue from the last successful step.

```bash
ip route
getent hosts packages.wazuh.com
sudo apt-get update
sudo apt-get install -y unzip curl ca-certificates
cd /home/labuser
umask 077
unzip -q healthcare-soc-handoff.zip -d healthcare-soc-handoff
mkdir -p healthcare-soc-runtime
install -m 600 healthcare-soc-handoff/runtime/secrets.json healthcare-soc-runtime/secrets.json
mv healthcare-soc-handoff/project healthcare-soc
cd healthcare-soc
bash scripts/setup-linux.sh
.venv/bin/python -m hospital_soc --help
```

For packet capture, use `sudo dpkg-reconfigure wireshark-common`, allow non-root captures for the lab group, then `sudo usermod -aG wireshark labuser`. Log out and back in, run `groups` and `dumpcap -D`, and find the lab interface recorded at checkpoint 3. Package installation alone does not verify capture permissions.

### 6. Install and check Wazuh on Ubuntu

The candidate native test driver expects **4.14.x**. Ask the phone tutor to check the official installation assistant for that series and the available matching Windows MSI before installing. If the current quickstart shows another series, choose the official 4.14 package path. Use the temporary NAT only for downloads. For a fresh VM the all-in-one assistant sequence is:

```bash
mkdir -p ~/wazuh-install
cd ~/wazuh-install
curl -fSLO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Installation prints a dashboard credential. Store it privately on the laptop and crop it from screenshots. If installation fails, preserve the first failing component and its error. Inspect its service log and the install log before retrying. Avoid overwrite/uninstall flags on a partially working installation. [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html)

```bash
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
dpkg-query -W wazuh-manager wazuh-indexer wazuh-dashboard filebeat
free -h
df -h /
```

Expect four active services. Record the exact Wazuh patch version. From the **Windows laptop browser**, open `https://10.77.0.10` and confirm authenticated dashboard access. If the page times out, test port 443 from Windows and check `sudo ss -lntp` in Ubuntu. Record any certificate warning and confirm the destination is your lab guest.

### 7. Enroll the Windows endpoint and enable monitoring

1. In the dashboard's agent deployment flow select **Windows**, manager **10.77.0.10**, agent name **hospital-win**. Use the official signed Windows agent MSI matching the guest Wazuh patch. In Administrator PowerShell inspect its signature with `Get-AuthenticodeSignature 'FULL-PATH-TO-MSI' | Select-Object Status,SignerCertificate`. Use the actual downloaded path. Require a valid Wazuh publisher signature. Run the matched deployment command, start the service and verify `Get-Service WazuhSvc`. On Ubuntu run `sudo /var/ossec/bin/agent_control -lc`; expect hospital-win active. If disconnected, test manager TCP ports 1514 and 1515 from Windows and inspect agent logs. [Windows deployment instructions](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html)
2. Back up the installed Windows agent's `ossec.conf`. Inspect its existing configuration. Merge `agent-localfile.rendered.xml` and `agent-fim.rendered.xml` from the Windows hospital runtime into the correct sections. Merge into the existing syscheck block if present. Confirm it monitors the hospital's `logs\app.jsonl` and exact `documents` directory. Restart WazuhSvc. Inspect the agent log for configuration errors and completed initial FIM scan.
3. On Ubuntu, follow `~/healthcare-soc/siem/manager-archives.md`: back up manager and Filebeat configs, enable JSON archives in the existing global section and archive forwarding in the existing Wazuh module. Restart the manager and Filebeat and check both services. Create or verify the `wazuh-archives-*` and `wazuh-alerts-*` data views. You will test the searchable archive with a real request in Session 3.
4. From `~/healthcare-soc`, install the shipped stamped candidate into the active manager rules directory. If a previous candidate exists, back it up outside the loaded rules directory first. Run `sudo install -m 640 -o root -g wazuh siem/healthcare_rules.xml /var/ossec/etc/rules/healthcare_rules.xml`, then `sudo /var/ossec/bin/wazuh-analysisd -t`. On success restart `wazuh-manager` and verify it is active. If the candidate was edited, follow the stamping/reload instructions in `docs/operator-handoff.md` before testing it.

## Session 3 — Prove the lab actually works

### 8. Isolate traffic and send one real request

Disconnect the temporary NAT NIC in VMware. In Ubuntu confirm the lab NIC still has `10.77.0.10/24` and `ip route get 10.77.0.1` selects it. Verify Windows SSH/dashboard reachability again. Measure host/guest UTC clock offset; for a quick bound, bracket an SSH `date -u` reading with Windows UTC readings, include fractional seconds, and retain the round-trip interval. The project requires ≤1 second for cross-host timing claims. Recheck clock offset in later sessions.

**Administrator PowerShell, Windows.** First inspect whether the named rule already exists. If absent, create this scoped rule:

```powershell
Get-NetFirewallRule -DisplayName 'Healthcare SOC hospital API' -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName 'Healthcare SOC hospital API' -Direction Inbound -Action Allow -Protocol TCP -LocalAddress 10.77.0.1 -LocalPort 8080 -RemoteAddress 10.77.0.10
```

**Ordinary PowerShell, Windows.** Keep this terminal open while running traffic:

```powershell
Set-Location "$env:USERPROFILE\OneDrive\Desktop\SOC Project"
.venv\Scripts\python.exe -m hospital_soc --config config\lab.local.json serve
```

**Ubuntu terminal A.** Set LABIF to the actual interface name from your notes. Start a short capture:

```bash
read -rp 'Verified host-only interface: ' LABIF
SMOKE="$HOME/evidence/smoke-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$SMOKE"
echo "$SMOKE"
dumpcap -i "$LABIF" -f 'host 10.77.0.1 and tcp port 8080' -w "$SMOKE/smoke.pcapng"
```

**Ubuntu terminal B.** Run `curl -i --max-time 5 http://10.77.0.1:8080/health`. Expect HTTP 200. Stop capture with Ctrl+C in terminal A. Run `tshark -r "$SMOKE/smoke.pcapng" -Y http.request` there. Match the response request ID with the Windows audit file and the indexed Wazuh archive event (`data.request_id`). Confirm the archive's agent is hospital-win and action is service_heartbeat. Save the safe evidence privately. If packets and the local audit exist but Discover is empty, check the data view, UTC window, local manager archives, then Filebeat forwarding. A benign health request may have no actionable alert.

### 9. Verify stability, FIM and native rules before long trials

- Observe at least 15 minutes under basic SOC operation. Save timestamped host/guest memory, swap, CPU and disk readings at the start, during the run and at the end, plus service statuses, dashboard responsiveness and agent connectivity. `free -h`, `vmstat 5 3`, `df -h /` and Task Manager provide useful readings.
- After the initial FIM inventory, exercise the project's bounded update on one designated dummy document. Record before/after SHA-256, actual syscheck path, endpoint and event timestamp. Use the project's restore procedure and verify the original digest. In the guest repository, `docs/operator-handoff.md` describes reset and evidence collection. Keep maintenance outside measured windows.
- In Ubuntu: `cd ~/healthcare-soc`, then `sudo .venv/bin/python scripts/verify-native-rules.py --output "$HOME/native-proof-$(date -u +%Y%m%dT%H%M%SZ)"`. The expiry cases take real time. Require the loaded-revision challenge plus 25 controls to pass. Save the full proof directory and transcripts, including failures.
- After these checks, you can hand off to the coding agent or continue the lab with your phone. The guest's `docs/operator-handoff.md` contains run commands and required evidence. Use the verified interface, fresh run directories and real timing. The next stages are a 30-minute calibration, three 10-minute benign holdouts, and three runs each of S1 account misuse, S2 file changes and S3 unusual export. Keep captures, source/archives/alerts, clocks, drop statistics, receiver receipts, per-run metrics and restoration evidence. Obtain the verified evaluator fixes before treating results as final. Stop on the first failed dependency and preserve the original evidence.

## Pause or return to Codex

1. Record the last successful checkpoint, exact error if any, exact Wazuh version, VMnet number, lab interface, and private evidence directory paths. A short text summary is enough for the phone.
2. Finish active captures with Ctrl+C. Stop the Windows hospital server with Ctrl+C if running. Shut down the guest with `sudo poweroff` and wait for VMware to show **Powered Off**. Reopen Codex once the VM has released its memory.
3. Paste: “I finished checkpoint __ in the phone guide. Windows lab IP __, guest IP __, interface __, SSH __, dashboard __, agent __, captured health request __, native checks __/26. Evidence is at __. The first failed step and error are __. Resume from here.”
