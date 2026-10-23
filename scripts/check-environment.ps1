param([string]$OutputPath = (Join-Path $PSScriptRoot '..\evidence\environment\host-facts.json'))
$ErrorActionPreference = 'Stop'
$pc = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = @(Get-CimInstance Win32_Processor)
$vmrunCandidates = @(
    'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe',
    'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
)
$vmrun = $vmrunCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
$vmList = @()
if ($vmrun) {
    $vmList = @(& $vmrun list)
    if ($LASTEXITCODE -ne 0) { throw 'VMware inventory failed; cannot infer that no VM is running.' }
}
$interfaces = @(Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress,PrefixLength)
$volume = New-Object System.IO.DriveInfo 'C'
$facts = [ordered]@{
    collected_at = [DateTime]::UtcNow.ToString('o')
    os = $os.Caption
    total_ram_gib = [math]::Round($pc.TotalPhysicalMemory / 1GB, 2)
    free_ram_gib = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    free_disk_gib = [math]::Round($volume.AvailableFreeSpace / 1GB, 2)
    logical_processors = [int]$pc.NumberOfLogicalProcessors
    administrator = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    hypervisor_present = [bool]$pc.HypervisorPresent
    virtualization_firmware_enabled = [bool]($cpu.VirtualizationFirmwareEnabled -contains $true)
    vmware_installed = [bool]$vmrun
    vmware_inventory = $vmList
    wazuh_agent_installed = [bool](Test-Path -LiteralPath 'C:\Program Files (x86)\ossec-agent\ossec.conf')
    capture_installed = [bool](Test-Path -LiteralPath 'C:\Program Files\Wireshark\dumpcap.exe')
    lab_vm_running = $null
    lab_network_verified = $null
    interfaces = $interfaces
    observations = @('Lab VM identity and isolation require explicit verification; an installed hypervisor is insufficient.', 'Firmware virtualization may be hidden by an active hypervisor; do not infer BIOS settings from one flag.')
}
$absolute = [System.IO.Path]::GetFullPath($OutputPath)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($absolute)) | Out-Null
[System.IO.File]::WriteAllText($absolute, ($facts | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding $false))
Write-Output $absolute
