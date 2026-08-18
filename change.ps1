# change.ps1 - Interactively edit .env (Ollama host, LLM provider, model, API key)
# without re-running the full setup wizard.
# After changing values, run '.\resume.ps1' to apply them (containers get recreated).

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$EnvFile = Join-Path $ScriptDir ".env"

if (-not (Test-Path $EnvFile)) {
    Write-Host "'.env' not found. Run '.\setup.ps1' first."
    exit 1
}

function Get-EnvValue {
    param([string]$Key)
    $line = Get-Content $EnvFile | Where-Object { $_ -match "^$Key=" } | Select-Object -First 1
    if ($line) { return ($line -split '=', 2)[1] } else { return "" }
}

function Set-EnvValue {
    param([string]$Key, [string]$Value)
    $lines = Get-Content $EnvFile
    $found = $false
    $newLines = foreach ($line in $lines) {
        if ($line -match "^$Key=") {
            $found = $true
            "$Key=$Value"
        } else {
            $line
        }
    }
    if (-not $found) {
        $newLines += "$Key=$Value"
    }
    $newLines | Set-Content -Path $EnvFile -Encoding UTF8
}

Write-Host "===================================================="
Write-Host "   VulnVerse - Change Settings"
Write-Host "===================================================="
Write-Host ""
Write-Host "Current settings:"
Write-Host "  OLLAMA_HOST  = $(Get-EnvValue 'OLLAMA_HOST')"
Write-Host "  LLM_PROVIDER = $(Get-EnvValue 'LLM_PROVIDER')"
Write-Host "  LLM_MODEL    = $(Get-EnvValue 'LLM_MODEL')"
Write-Host "  API_PROVIDER = $(Get-EnvValue 'API_PROVIDER')"
$currentKey = Get-EnvValue 'API_KEY'
$keyDisplay = if ([string]::IsNullOrWhiteSpace($currentKey)) { "(empty)" } else { "(set, hidden)" }
Write-Host "  API_KEY      = $keyDisplay"
Write-Host ""
Write-Host "What do you want to change?"
Write-Host "  1) Ollama host (IP:port)"
Write-Host "  2) Switch LLM provider (Ollama <-> API)"
Write-Host "  3) Change model name only"
Write-Host "  4) Change API key"
Write-Host "  5) Edit .env manually (Notepad)"
Write-Host "  6) Just show current values (already shown above)"
Write-Host "  7) Change data storage location (DB, uploads, logs)"
Write-Host "  0) Exit"
Write-Host ""
$choice = Read-Host "Choice"

switch ($choice) {
    "1" {
        $ip = Read-Host "Ollama IP address"
        $portInput = Read-Host "Ollama port [11434]"
        $port = if ([string]::IsNullOrWhiteSpace($portInput)) { "11434" } else { $portInput }
        Set-EnvValue "OLLAMA_HOST" "http://${ip}:${port}"
        Write-Host "OLLAMA_HOST updated."
    }
    "2" {
        Write-Host "1) Ollama (local models)"
        Write-Host "2) API Key (cloud provider)"
        $pInput = Read-Host "Select provider [1]"
        $p = if ([string]::IsNullOrWhiteSpace($pInput)) { "1" } else { $pInput }
        if ($p -eq "2") {
            Set-EnvValue "LLM_PROVIDER" "api"
            Write-Host "1) claude  2) openai  3) gemini  4) nvidia  5) openrouter"
            $apInput = Read-Host "API provider [1]"
            $ap = if ([string]::IsNullOrWhiteSpace($apInput)) { "1" } else { $apInput }
            switch ($ap) {
                "1" { Set-EnvValue "API_PROVIDER" "claude" }
                "2" { Set-EnvValue "API_PROVIDER" "openai" }
                "3" { Set-EnvValue "API_PROVIDER" "gemini" }
                "4" { Set-EnvValue "API_PROVIDER" "nvidia" }
                "5" { Set-EnvValue "API_PROVIDER" "openrouter" }
                default { Set-EnvValue "API_PROVIDER" "claude" }
            }
            $mdl = Read-Host "Model name"
            if (-not [string]::IsNullOrWhiteSpace($mdl)) { Set-EnvValue "LLM_MODEL" $mdl }
            $key = Read-Host "API key"
            Set-EnvValue "API_KEY" $key
        } else {
            Set-EnvValue "LLM_PROVIDER" "ollama"
            $mdl = Read-Host "Model name (e.g. mistral:latest)"
            if (-not [string]::IsNullOrWhiteSpace($mdl)) { Set-EnvValue "LLM_MODEL" $mdl }
        }
        Write-Host "Provider settings updated."
    }
    "3" {
        $mdl = Read-Host "New model name"
        if (-not [string]::IsNullOrWhiteSpace($mdl)) { Set-EnvValue "LLM_MODEL" $mdl }
        Write-Host "LLM_MODEL updated."
    }
    "4" {
        $key = Read-Host "New API key"
        Set-EnvValue "API_KEY" $key
        Write-Host "API_KEY updated."
    }
    "5" {
        Start-Process notepad.exe $EnvFile -Wait
        Write-Host ".env saved."
    }
    "6" { exit 0 }
    "7" {
        Write-Host ""
        Write-Host "Current DATA_PATH: $(Get-EnvValue 'DATA_PATH')"
        Write-Host "This is where lab data (DB, uploads, logs) will be stored."
        Write-Host "Example: D:\vulnverse-data"
        Write-Host ""
        $newPath = Read-Host "New data path"
        if (-not [string]::IsNullOrWhiteSpace($newPath)) {
            try {
                New-Item -ItemType Directory -Force -Path $newPath | Out-Null
            } catch {
                Write-Host "Could not create '$newPath'. Check the path/permissions and try again."
                exit 1
            }
            Set-EnvValue "DATA_PATH" $newPath
            Write-Host "DATA_PATH updated to: $newPath"
            Write-Host ""
            Write-Host "IMPORTANT: If you had existing data under the old path, copy it over"
            Write-Host "manually before resuming, e.g.:"
            Write-Host "  Copy-Item -Recurse .\data\* '$newPath\'"
            Write-Host ""
            Write-Host "Your docker-compose.yml volume sections must reference `${DATA_PATH}"
            Write-Host "for this to actually take effect (see README)."
        }
    }
    "0" { exit 0 }
    default {
        Write-Host "Invalid choice."
        exit 1
    }
}

Write-Host ""
Write-Host "Run '.\resume.ps1' to apply the changes (containers will be recreated)."
