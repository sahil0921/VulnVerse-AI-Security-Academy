#!/bin/bash

set -e

clear

echo "===================================================="
echo "     VulnVerse AI Security Lab - Setup Wizard"
echo "===================================================="
echo

###########################################
# Docker Checks
###########################################

echo "[1/8] Checking Docker..."

if ! command -v docker >/dev/null 2>&1; then
    echo "❌ Docker is not installed."
    echo "Install Docker first."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker daemon is not running."
    echo "Start Docker and try again."
    exit 1
fi

echo "✅ Docker OK"

###########################################
# Docker Compose
###########################################

echo
echo "[2/8] Checking Docker Compose..."

if ! docker compose version >/dev/null 2>&1; then
    echo "❌ Docker Compose is not installed."
    exit 1
fi

echo "✅ Docker Compose OK"

###########################################
# Validate compose file
###########################################

echo
echo "[3/8] Checking docker-compose.yml..."

if ! docker compose config >/dev/null 2>&1; then
    echo
    echo "❌ docker-compose.yml contains errors."
    echo "Fix the compose file before continuing."
    exit 1
fi

echo "✅ docker-compose.yml OK"

###########################################
# Ollama Host (always asked — used for Ollama
# provider, and harmless if API provider is chosen)
###########################################

echo
echo "===================================================="
echo "Ollama Configuration"
echo "===================================================="

while true
do
    read -p "Enter Ollama IP Address: " OLLAMA_IP

    if [[ "$OLLAMA_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        break
    fi

    echo "Invalid IP format."
done

read -p "Enter Ollama Port [11434]: " OLLAMA_PORT

OLLAMA_PORT=${OLLAMA_PORT:-11434}

OLLAMA_URL="http://${OLLAMA_IP}:${OLLAMA_PORT}"

###########################################
# LLM Provider Selection
###########################################

echo
echo "===================================================="
echo "LLM Provider"
echo "===================================================="
echo "1) Ollama (local models)"
echo "2) API Key (cloud provider)"
read -p "Select provider [1]: " PROVIDER_CHOICE
PROVIDER_CHOICE=${PROVIDER_CHOICE:-1}

API_PROVIDER=""
API_KEY=""
LLM_MODEL=""

if [[ "$PROVIDER_CHOICE" == "2" ]]; then
    LLM_PROVIDER="api"
    echo
    echo "Select API provider:"
    echo "1) Claude (Anthropic)"
    echo "2) OpenAI"
    echo "3) Gemini (Google)"
    echo "4) NVIDIA NIM"
    echo "5) OpenRouter"
    read -p "Choice [1]: " API_CHOICE
    API_CHOICE=${API_CHOICE:-1}

    case $API_CHOICE in
        1) API_PROVIDER="claude";     DEFAULT_MODEL="claude-sonnet-4-6" ;;
        2) API_PROVIDER="openai";     DEFAULT_MODEL="gpt-4o" ;;
        3) API_PROVIDER="gemini";     DEFAULT_MODEL="gemini-2.5-flash" ;;
        4) API_PROVIDER="nvidia";     DEFAULT_MODEL="meta/llama-3.1-70b-instruct" ;;
        5) API_PROVIDER="openrouter"; DEFAULT_MODEL="anthropic/claude-sonnet-4.6" ;;
        *) API_PROVIDER="claude";     DEFAULT_MODEL="claude-sonnet-4-6" ;;
    esac

    read -p "Enter API Key: " API_KEY
    read -p "Model name [$DEFAULT_MODEL]: " CUSTOM_MODEL
    LLM_MODEL=${CUSTOM_MODEL:-$DEFAULT_MODEL}

else
    LLM_PROVIDER="ollama"
    echo
    echo "Select Ollama model family:"
    echo "1) Llama    (llama3.2:1b / llama3.1:8b)"
    echo "2) Qwen     (qwen2.5:3b / qwen3:4b)"
    echo "3) Granite  (granite3-moe / granite3.1)"
    echo "4) Mistral  (mistral:latest / mistral:7b)"
    echo "5) Phi      (phi4-mini)"
    echo "6) Gemma    (gemma3:4b)"
    echo "7) Other    (type any custom Ollama model name)"
    read -p "Choice [4]: " FAMILY_CHOICE
    FAMILY_CHOICE=${FAMILY_CHOICE:-4}

    case $FAMILY_CHOICE in
        1)
            echo "  a) llama3.2:1b"
            echo "  b) llama3.1:8b"
            read -p "  Choice [a]: " SUB
            [[ "$SUB" == "b" ]] && LLM_MODEL="llama3.1:8b" || LLM_MODEL="llama3.2:1b"
            ;;
        2)
            echo "  a) qwen2.5:3b"
            echo "  b) qwen3:4b"
            read -p "  Choice [a]: " SUB
            [[ "$SUB" == "b" ]] && LLM_MODEL="qwen3:4b" || LLM_MODEL="qwen2.5:3b"
            ;;
        3)
            echo "  a) granite3-moe"
            echo "  b) granite3.1"
            read -p "  Choice [a]: " SUB
            [[ "$SUB" == "b" ]] && LLM_MODEL="granite3.1" || LLM_MODEL="granite3-moe"
            ;;
        4)
            echo "  a) mistral:latest"
            echo "  b) mistral:7b"
            read -p "  Choice [a]: " SUB
            [[ "$SUB" == "b" ]] && LLM_MODEL="mistral:7b" || LLM_MODEL="mistral:latest"
            ;;
        5) LLM_MODEL="phi4-mini" ;;
        6) LLM_MODEL="gemma3:4b" ;;
        7)
            read -p "  Enter exact Ollama model name (e.g. tinyllama, deepseek-r1:1.5b): " CUSTOM
            LLM_MODEL=${CUSTOM:-mistral:latest}
            ;;
        *) LLM_MODEL="mistral:latest" ;;
    esac
fi

echo
echo "✅ Selected: LLM_PROVIDER=$LLM_PROVIDER, LLM_MODEL=$LLM_MODEL${API_PROVIDER:+, API_PROVIDER=$API_PROVIDER}"

###########################################
# Create .env
###########################################

echo
echo "[4/8] Creating .env..."

cat > .env <<EOF
OLLAMA_HOST=$OLLAMA_URL
LLM_PROVIDER=$LLM_PROVIDER
LLM_MODEL=$LLM_MODEL
API_PROVIDER=$API_PROVIDER
API_KEY=$API_KEY
EOF

echo "✅ .env created."

###########################################
# Test Ollama (only meaningful if provider = ollama,
# but harmless to check either way since OLLAMA_HOST
# is still saved for labs that hardcode it)
###########################################

echo
echo "[5/8] Testing Ollama..."

if curl -sf "$OLLAMA_URL/api/tags" >/dev/null 2>&1
then
    echo "✅ Ollama reachable."
else
    echo
    echo "⚠ Cannot connect to Ollama."
    echo
    echo "Verify:"
    echo "  1. ollama serve"
    echo "  2. OLLAMA_HOST=0.0.0.0"
    echo "  3. Firewall allows port $OLLAMA_PORT"
    echo "  4. Correct Windows IP"

    if [[ "$LLM_PROVIDER" == "api" ]]; then
        echo
        echo "Note: You selected an API provider ($API_PROVIDER), so Ollama"
        echo "connectivity is not required for the LLM-based labs to work."
    fi

    echo
    read -p "Continue anyway? (y/N): " ans

    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 1
    fi
fi

###########################################
# Models
###########################################

echo
echo "[6/8] Required Ollama Models"
echo

if [[ "$LLM_PROVIDER" == "ollama" ]]; then
    echo "You selected: $LLM_MODEL"
    echo
    echo "⚠ Make sure this model is pulled on your Ollama host:"
    echo "  ollama pull $LLM_MODEL"
    echo
fi

echo "Mandatory (used by default across labs unless overridden):"
echo "  ollama pull mistral:latest"
echo "  ollama pull qwen2.5:3b"
echo "  ollama pull llama3.2:1b"
echo
echo "Optional:"
echo "  ollama pull phi4-mini"
echo "  ollama pull gemma3:4b"
echo "  ollama pull qwen3:4b"
echo "  ollama pull mistral:7b"
echo "  ollama pull granite3-moe"
echo "  ollama pull granite3.1"
echo "  ollama pull llama3.1:8b"
echo

read -p "Press ENTER when models are ready..."

###########################################
# API Key sanity check
###########################################

if [[ "$LLM_PROVIDER" == "api" ]]; then
    echo
    echo "[7/8] Checking API key..."
    if [[ -z "$API_KEY" ]]; then
        echo "⚠ No API key entered. LLM-based labs using the 'api' provider will fail."
        read -p "Continue anyway? (y/N): " ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            echo "Setup cancelled."
            exit 1
        fi
    else
        echo "✅ API key set for provider: $API_PROVIDER"
    fi
else
    echo
    echo "[7/8] Skipping API key check (using Ollama)."
fi

###########################################
# Build & Start
###########################################

echo
echo "[8/8] Building Docker Images..."
echo "This may take several minutes..."
echo

docker compose build

echo
echo "Starting containers..."

docker compose up -d

echo
echo "Container Status"
echo "=============================="

docker compose ps

echo
echo "===================================================="
echo "Setup Completed Successfully"
echo "===================================================="

echo
echo "Dashboard:"
echo "http://localhost:8080"

echo
echo "LLM Configuration:"
echo "  Provider: $LLM_PROVIDER"
if [[ "$LLM_PROVIDER" == "ollama" ]]; then
    echo "  Model: $LLM_MODEL"
else
    echo "  API Provider: $API_PROVIDER"
    echo "  Model: $LLM_MODEL"
fi

echo
echo "Useful Commands:"
echo "docker compose ps"
echo "docker compose logs -f"
echo "docker compose down"
echo "docker compose restart <service>"
echo
echo "To change LLM provider later, edit .env and run:"
echo "docker compose up -d --force-recreate"
echo
