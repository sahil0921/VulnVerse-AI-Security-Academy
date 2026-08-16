# status.ps1 - Shows which containers are running + disk usage.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

docker compose ps
Write-Host ""
Write-Host "Docker disk usage:"
docker system df
