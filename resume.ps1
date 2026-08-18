# resume.ps1 - Turns existing containers back ON (no rebuild).
# Uses 'docker compose up -d' so that if .env changed (via change.ps1) or a
# container is missing, it gets recreated/fixed automatically.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

if (-not (Test-Path ".env")) {
    Write-Host "'.env' not found. Run '.\setup.ps1' first."
    exit 1
}

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$images = docker compose images -q 2>$null
$ErrorActionPreference = $prevEAP

if ([string]::IsNullOrWhiteSpace($images)) {
    Write-Host "No images found. Run '.\setup.ps1' first."
    exit 1
}

Write-Host "Starting containers..."

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker compose up -d
$ErrorActionPreference = $prevEAP
if ($LASTEXITCODE -ne 0) { Write-Host "Failed to start containers."; exit 1 }

Write-Host ""

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker compose ps
$ErrorActionPreference = $prevEAP

Write-Host ""
Write-Host "Lab is back ON!"
Write-Host "  -> Dashboard: http://localhost:8080"
