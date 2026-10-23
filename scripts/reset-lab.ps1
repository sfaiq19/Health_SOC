param([string]$Runtime = "$env:USERPROFILE\HealthcareSOCLab\hospital")
$ErrorActionPreference = 'Stop'
& .venv\Scripts\python.exe -m hospital_soc --runtime $Runtime restore
if ($LASTEXITCODE -ne 0) { throw 'Restore failed or was refused; do not discard the error' }
