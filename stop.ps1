# stop.ps1 - Stops containers WITHOUT deleting them. Data/volumes stay safe.
# Use '.\resume.ps1' to turn it back on.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "Stopping containers (data will stay safe)..."
docker compose stop
if ($LASTEXITCODE -ne 0) { Write-Host "Failed to stop containers."; exit 1 }

Write-Host ""
Write-Host "Lab stopped. Run '.\resume.ps1' to start it again."
