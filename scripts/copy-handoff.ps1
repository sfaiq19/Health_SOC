param([string]$Runtime = "$env:USERPROFILE\HealthcareSOCLab\hospital")
$ErrorActionPreference = 'Stop'
$archive = Join-Path $Runtime 'private-handoff.zip'
if (-not (Test-Path -LiteralPath $archive)) { throw 'Run prepare-handoff.py first' }
if (-not (Get-Command scp -ErrorAction SilentlyContinue)) { throw 'Windows OpenSSH client is required for the private copy' }
& scp $archive 'labuser@10.77.0.10:/home/labuser/healthcare-soc-handoff.zip'
if ($LASTEXITCODE -ne 0) { throw 'Private handoff copy failed' }
Write-Output 'In the VM follow docs/operator-handoff.md to extract the private runtime and source.'
