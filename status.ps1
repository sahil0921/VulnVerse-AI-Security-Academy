# status.ps1 - Shows which containers are running + disk usage.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker compose ps
$ErrorActionPreference = $prevEAP

Write-Host ""
Write-Host "Docker disk usage:"
docker system df
