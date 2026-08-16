#!/usr/bin/env bash
# change.sh - Interactively edit .env (Ollama host, LLM provider, model, API key)
# without re-running the full setup wizard.
# After changing values, run './resume.sh' to apply them (containers get recreated).

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "❌ .env not found. Run './setup.sh' first."
    exit 1
fi

set_kv() {
    local key="$1"
    local value="$2"
    local escaped_value
    escaped_value=$(printf '%s\n' "$value" | sed -e 's/[\/&]/\\&/g')

    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s/^${key}=.*/${key}=${escaped_value}/" "$ENV_FILE"
    else
        echo "${key}=${value}" >> "$ENV_FILE"
    fi
}

get_kv() {
    local key="$1"
    grep "^${key}=" "$ENV_FILE" 2>/dev/null | head -n1 | cut -d'=' -f2-
}

echo "===================================================="
echo "   VulnVerse - Change Settings"
echo "===================================================="
echo
echo "Current settings:"
echo "  OLLAMA_HOST  = $(get_kv OLLAMA_HOST)"
echo "  LLM_PROVIDER = $(get_kv LLM_PROVIDER)"
echo "  LLM_MODEL    = $(get_kv LLM_MODEL)"
echo "  API_PROVIDER = $(get_kv API_PROVIDER)"
echo "  API_KEY      = $( [ -n "$(get_kv API_KEY)" ] && echo '(set, hidden)' || echo '(empty)' )"
echo
echo "What do you want to change?"
echo "  1) Ollama host (IP:port)"
echo "  2) Switch LLM provider (Ollama <-> API)"
echo "  3) Change model name only"
echo "  4) Change API key"
echo "  5) Edit .env manually (nano)"
echo "  6) Just show current values (already shown above)"
echo "  0) Exit"
echo
read -r -p "Choice: " CHOICE

case "$CHOICE" in
    1)
        read -r -p "Ollama IP address: " OIP
        read -r -p "Ollama port [11434]: " OPORT
        OPORT=${OPORT:-11434}
        set_kv "OLLAMA_HOST" "http://${OIP}:${OPORT}"
        echo "✅ OLLAMA_HOST updated."
        ;;
    2)
        echo "1) Ollama (local models)"
        echo "2) API Key (cloud provider)"
        read -r -p "Select provider [1]: " P
        P=${P:-1}
        if [[ "$P" == "2" ]]; then
            set_kv "LLM_PROVIDER" "api"
            echo "1) claude  2) openai  3) gemini  4) nvidia  5) openrouter"
            read -r -p "API provider [1]: " AP
            case ${AP:-1} in
                1) set_kv "API_PROVIDER" "claude" ;;
                2) set_kv "API_PROVIDER" "openai" ;;
                3) set_kv "API_PROVIDER" "gemini" ;;
                4) set_kv "API_PROVIDER" "nvidia" ;;
                5) set_kv "API_PROVIDER" "openrouter" ;;
                *) set_kv "API_PROVIDER" "claude" ;;
            esac
            read -r -p "Model name: " MDL
            [ -n "$MDL" ] && set_kv "LLM_MODEL" "$MDL"
            read -r -p "API key: " KEY
            set_kv "API_KEY" "$KEY"
        else
            set_kv "LLM_PROVIDER" "ollama"
            read -r -p "Model name (e.g. mistral:latest): " MDL
            [ -n "$MDL" ] && set_kv "LLM_MODEL" "$MDL"
        fi
        echo "✅ Provider settings updated."
        ;;
    3)
        read -r -p "New model name: " MDL
        [ -n "$MDL" ] && set_kv "LLM_MODEL" "$MDL"
        echo "✅ LLM_MODEL updated."
        ;;
    4)
        read -r -p "New API key: " KEY
        set_kv "API_KEY" "$KEY"
        echo "✅ API_KEY updated."
        ;;
    5)
        "${EDITOR:-nano}" "$ENV_FILE"
        echo "✅ .env saved."
        ;;
    6)
        exit 0
        ;;
    0)
        exit 0
        ;;
    *)
        echo "❌ Invalid choice."
        exit 1
        ;;
esac

echo
echo "⚠ Run './resume.sh' to apply the changes (containers will be recreated)."
