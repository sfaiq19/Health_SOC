param([string]$Python = 'python', [string]$Runtime = "$env:USERPROFILE\HealthcareSOCLab\hospital")
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    & $Python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python venv creation failed' }
}
& .venv\Scripts\python.exe -m pip install -r requirements-lock.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
& .venv\Scripts\python.exe -m pip install --no-deps -e .
if ($LASTEXITCODE -ne 0) { throw 'Package installation failed' }
& .venv\Scripts\python.exe -m hospital_soc --runtime $Runtime seed --seed 101
if ($LASTEXITCODE -ne 0) { throw 'Seeding refused or failed; preserve existing runtime and inspect it' }
Write-Output "Hospital runtime created at $Runtime. Disposable credentials stay in its secrets.json."
Write-Output 'VM, Wazuh, firewall, and capture acceptance remain separate.'
