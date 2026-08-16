# clean.ps1 - PERMANENT cleanup. Deletes containers + volumes + images.
# Frees up disk space. After this, run '.\setup.ps1' again to rebuild.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host "This action is PERMANENT. It will delete:"
Write-Host "    - All containers"
Write-Host "    - All volumes (lab data, DB, uploaded files - EVERYTHING)"
Write-Host "    - All images (you'll need to rebuild on next setup)"
Write-Host ""
$confirm = Read-Host "Are you sure? Type 'yes' to confirm"

if ($confirm -ne "yes") {
    Write-Host "Cancelled. Nothing was deleted."
    exit 0
}

Write-Host ""
Write-Host "Cleaning up everything..."
docker compose down -v --rmi all --remove-orphans
if ($LASTEXITCODE -ne 0) { Write-Host "Cleanup encountered an error."; exit 1 }

Write-Host ""
Write-Host "Fully cleaned up. Disk space has been freed."
Write-Host "Run '.\setup.ps1' if you want to use it again."
