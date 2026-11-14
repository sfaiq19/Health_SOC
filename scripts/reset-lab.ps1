param(
    [string]$Runtime = "$env:USERPROFILE\HealthcareSOCLab\hospital",
    [string]$ReceiptPath = ""
)
$ErrorActionPreference = 'Stop'
if (-not $ReceiptPath) {
    $stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssffffffZ')
    $ReceiptPath = Join-Path $Runtime "restore-receipts\reset-$stamp.json"
}
& .venv\Scripts\python.exe -m hospital_soc --runtime $Runtime restore --receipt $ReceiptPath
if ($LASTEXITCODE -ne 0) { throw 'Restore failed or was refused; do not discard the error' }
