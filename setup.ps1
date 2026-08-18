# setup.ps1 - Run this the FIRST time only. Asks for LLM/Ollama config,
# builds images, creates and starts containers.
# After this, use '.\resume.ps1' for everyday on/off, and '.\change.ps1'
# if you need to update the API key / model / Ollama settings later.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Clear-Host

Write-Host "===================================================="
Write-Host "     VulnVerse AI Security Lab - Setup Wizard"
Write-Host "===================================================="
Write-Host ""

###########################################
# Docker Checks
###########################################

Write-Host "[1/8] Checking Docker..."

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker is not installed."
    Write-Host "Install Docker Desktop first: https://docs.docker.com/desktop/install/windows-install/"
    exit 1
}

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker daemon is not running."
    Write-Host "Start Docker Desktop and try again."
    exit 1
}

Write-Host "Docker OK"

###########################################
# Docker Compose
###########################################

Write-Host ""
Write-Host "[2/8] Checking Docker Compose..."

docker compose version *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker Compose is not installed."
    exit 1
}

Write-Host "Docker Compose OK"

###########################################
# Validate compose file
###########################################

Write-Host ""
Write-Host "[3/8] Checking docker-compose.yml..."

$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
docker compose config *> $null
$ErrorActionPreference = $prevEAP
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "docker-compose.yml contains errors."
    Write-Host "Fix the compose file before continuing."
    exit 1
}

Write-Host "docker-compose.yml OK"

###########################################
# Ollama Host (always asked - used for Ollama
# provider, and harmless if API provider is chosen)
###########################################

Write-Host ""
Write-Host "===================================================="
Write-Host "Ollama Configuration"
Write-Host "===================================================="

$ipPattern = '^(\d{1,3}\.){3}\d{1,3}$'
do {
    $OllamaIp = Read-Host "Enter Ollama IP Address"
    if ($OllamaIp -notmatch $ipPattern) {
        Write-Host "Invalid IP format."
    }
} while ($OllamaIp -notmatch $ipPattern)

$OllamaPortInput = Read-Host "Enter Ollama Port [11434]"
$OllamaPort = if ([string]::IsNullOrWhiteSpace($OllamaPortInput)) { "11434" } else { $OllamaPortInput }

$OllamaUrl = "http://${OllamaIp}:${OllamaPort}"

###########################################
# LLM Provider Selection
###########################################

Write-Host ""
Write-Host "===================================================="
Write-Host "LLM Provider"
Write-Host "===================================================="
Write-Host "1) Ollama (local models)"
Write-Host "2) API Key (cloud provider)"
$ProviderChoiceInput = Read-Host "Select provider [1]"
$ProviderChoice = if ([string]::IsNullOrWhiteSpace($ProviderChoiceInput)) { "1" } else { $ProviderChoiceInput }

$ApiProvider = ""
$ApiKey = ""
$LlmModel = ""
$LlmProvider = ""

if ($ProviderChoice -eq "2") {
    $LlmProvider = "api"
    Write-Host ""
    Write-Host "Select API provider:"
    Write-Host "1) Claude (Anthropic)"
    Write-Host "2) OpenAI"
    Write-Host "3) Gemini (Google)"
    Write-Host "4) NVIDIA NIM"
    Write-Host "5) OpenRouter"
    $ApiChoiceInput = Read-Host "Choice [1]"
    $ApiChoice = if ([string]::IsNullOrWhiteSpace($ApiChoiceInput)) { "1" } else { $ApiChoiceInput }

    switch ($ApiChoice) {
        "1" { $ApiProvider = "claude";     $DefaultModel = "claude-sonnet-4-6" }
        "2" { $ApiProvider = "openai";     $DefaultModel = "gpt-4o" }
        "3" { $ApiProvider = "gemini";     $DefaultModel = "gemini-2.5-flash" }
        "4" { $ApiProvider = "nvidia";     $DefaultModel = "meta/llama-3.1-70b-instruct" }
        "5" { $ApiProvider = "openrouter"; $DefaultModel = "anthropic/claude-sonnet-4.6" }
        default { $ApiProvider = "claude"; $DefaultModel = "claude-sonnet-4-6" }
    }

    $ApiKey = Read-Host "Enter API Key"
    $CustomModel = Read-Host "Model name [$DefaultModel]"
    $LlmModel = if ([string]::IsNullOrWhiteSpace($CustomModel)) { $DefaultModel } else { $CustomModel }

} else {
    $LlmProvider = "ollama"
    Write-Host ""
    Write-Host "Select Ollama model family:"
    Write-Host "1) Llama    (llama3.2:1b / llama3.1:8b)"
    Write-Host "2) Qwen     (qwen2.5:3b / qwen3:4b)"
    Write-Host "3) Granite  (granite3-moe / granite3.1)"
    Write-Host "4) Mistral  (mistral:latest / mistral:7b)"
    Write-Host "5) Phi      (phi4-mini)"
    Write-Host "6) Gemma    (gemma3:4b)"
    Write-Host "7) Other    (type any custom Ollama model name)"
    $FamilyChoiceInput = Read-Host "Choice [4]"
    $FamilyChoice = if ([string]::IsNullOrWhiteSpace($FamilyChoiceInput)) { "4" } else { $FamilyChoiceInput }

    switch ($FamilyChoice) {
        "1" {
            Write-Host "  a) llama3.2:1b"
            Write-Host "  b) llama3.1:8b"
            $Sub = Read-Host "  Choice [a]"
            $LlmModel = if ($Sub -eq "b") { "llama3.1:8b" } else { "llama3.2:1b" }
        }
        "2" {
            Write-Host "  a) qwen2.5:3b"
            Write-Host "  b) qwen3:4b"
            $Sub = Read-Host "  Choice [a]"
            $LlmModel = if ($Sub -eq "b") { "qwen3:4b" } else { "qwen2.5:3b" }
        }
        "3" {
            Write-Host "  a) granite3-moe"
            Write-Host "  b) granite3.1"
            $Sub = Read-Host "  Choice [a]"
            $LlmModel = if ($Sub -eq "b") { "granite3.1" } else { "granite3-moe" }
        }
        "4" {
            Write-Host "  a) mistral:latest"
            Write-Host "  b) mistral:7b"
            $Sub = Read-Host "  Choice [a]"
            $LlmModel = if ($Sub -eq "b") { "mistral:7b" } else { "mistral:latest" }
        }
        "5" { $LlmModel = "phi4-mini" }
        "6" { $LlmModel = "gemma3:4b" }
        "7" {
            $Custom = Read-Host "  Enter exact Ollama model name (e.g. tinyllama, deepseek-r1:1.5b)"
            $LlmModel = if ([string]::IsNullOrWhiteSpace($Custom)) { "mistral:latest" } else { $Custom }
        }
        default { $LlmModel = "mistral:latest" }
    }
}

Write-Host ""
Write-Host "Selected: LLM_PROVIDER=$LlmProvider, LLM_MODEL=$LlmModel$(if ($ApiProvider) { ", API_PROVIDER=$ApiProvider" })"

###########################################
# Create .env
###########################################

Write-Host ""
Write-Host "[4/8] Creating .env..."

@"
OLLAMA_HOST=$OllamaUrl
LLM_PROVIDER=$LlmProvider
LLM_MODEL=$LlmModel
API_PROVIDER=$ApiProvider
API_KEY=$ApiKey
"@ | Set-Content -Path ".env" -Encoding UTF8

Write-Host ".env created."

###########################################
# Test Ollama (only meaningful if provider = ollama,
# but harmless to check either way since OLLAMA_HOST
# is still saved for labs that hardcode it)
###########################################

Write-Host ""
Write-Host "[5/8] Testing Ollama..."

$OllamaReachable = $false
try {
    $response = Invoke-WebRequest -Uri "$OllamaUrl/api/tags" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) { $OllamaReachable = $true }
} catch {
    $OllamaReachable = $false
}

if ($OllamaReachable) {
    Write-Host "Ollama reachable."
} else {
    Write-Host ""
    Write-Host "Cannot connect to Ollama."
    Write-Host ""
    Write-Host "Verify:"
    Write-Host "  1. ollama serve is running"
    Write-Host "  2. OLLAMA_HOST=0.0.0.0 (if Ollama runs elsewhere/WSL/another machine)"
    Write-Host "  3. Windows Firewall allows port $OllamaPort"
    Write-Host "  4. Correct IP address"

    if ($LlmProvider -eq "api") {
        Write-Host ""
        Write-Host "Note: You selected an API provider ($ApiProvider), so Ollama"
        Write-Host "connectivity is not required for the LLM-based labs to work."
    }

    Write-Host ""
    $ans = Read-Host "Continue anyway? (y/N)"
    if ($ans -notmatch '^[Yy]$') {
        Write-Host "Setup cancelled."
        exit 1
    }
}

###########################################
# Models
###########################################

Write-Host ""
Write-Host "[6/8] Required Ollama Models"
Write-Host ""

if ($LlmProvider -eq "ollama") {
    Write-Host "You selected: $LlmModel"
    Write-Host ""
    Write-Host "Make sure this model is pulled on your Ollama host:"
    Write-Host "  ollama pull $LlmModel"
    Write-Host ""
}

Write-Host "Mandatory (used by default across labs unless overridden):"
Write-Host "  ollama pull mistral:latest"
Write-Host "  ollama pull qwen2.5:3b"
Write-Host "  ollama pull llama3.2:1b"
Write-Host ""
Write-Host "Optional:"
Write-Host "  ollama pull phi4-mini"
Write-Host "  ollama pull gemma3:4b"
Write-Host "  ollama pull qwen3:4b"
Write-Host "  ollama pull mistral:7b"
Write-Host "  ollama pull granite3-moe"
Write-Host "  ollama pull granite3.1"
Write-Host "  ollama pull llama3.1:8b"
Write-Host ""

Read-Host "Press ENTER when models are ready"

###########################################
# API Key sanity check
###########################################

if ($LlmProvider -eq "api") {
    Write-Host ""
    Write-Host "[7/8] Checking API key..."
    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-Host "No API key entered. LLM-based labs using the 'api' provider will fail."
        $ans = Read-Host "Continue anyway? (y/N)"
        if ($ans -notmatch '^[Yy]$') {
            Write-Host "Setup cancelled."
            exit 1
        }
    } else {
        Write-Host "API key set for provider: $ApiProvider"
    }
} else {
    Write-Host ""
    Write-Host "[7/8] Skipping API key check (using Ollama)."
}

###########################################
# Build & Start
###########################################

Write-Host ""
Write-Host "[8/8] Building Docker Images..."
Write-Host "This may take several minutes..."
Write-Host ""

$MaxBuildRetries = 3
$BuildSucceeded = $false

for ($attempt = 1; $attempt -le $MaxBuildRetries; $attempt++) {
    if ($attempt -gt 1) {
        Write-Host ""
        Write-Host "Retrying build (attempt $attempt of $MaxBuildRetries)..."
        Write-Host "Note: previous failure was likely a transient download issue"
        Write-Host "(hash mismatch from a corrupted/interrupted parallel download)."
        Write-Host ""
    }

    docker compose build
    if ($LASTEXITCODE -eq 0) {
        $BuildSucceeded = $true
        break
    }

    Write-Host ""
    Write-Host "Build attempt $attempt failed."
}

if (-not $BuildSucceeded) {
    Write-Host ""
    Write-Host "Build failed after $MaxBuildRetries attempts."
    Write-Host "Try running manually with no cache for just the failing service(s):"
    Write-Host "  docker compose build --no-cache <service-name>"
    exit 1
}

Write-Host ""
Write-Host "Starting containers..."

docker compose up -d
if ($LASTEXITCODE -ne 0) { Write-Host "Failed to start containers."; exit 1 }

Write-Host ""
Write-Host "Container Status"
Write-Host "=============================="

docker compose ps

Write-Host ""
Write-Host "===================================================="
Write-Host "Setup Completed Successfully"
Write-Host "===================================================="

Write-Host ""
Write-Host "Dashboard:"
Write-Host "http://localhost:8080"

Write-Host ""
Write-Host "LLM Configuration:"
Write-Host "  Provider: $LlmProvider"
if ($LlmProvider -eq "ollama") {
    Write-Host "  Model: $LlmModel"
} else {
    Write-Host "  API Provider: $ApiProvider"
    Write-Host "  Model: $LlmModel"
}

Write-Host ""
Write-Host "Useful Commands:"
Write-Host "  .\resume.ps1   - turn the lab back on (no rebuild)"
Write-Host "  .\stop.ps1     - stop containers, keep data"
Write-Host "  .\status.ps1   - check running containers"
Write-Host "  .\change.ps1   - change API key / model / Ollama settings later"
Write-Host "  .\clean.ps1    - permanently remove everything"
Write-Host ""
