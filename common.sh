#!/usr/bin/env bash
# common.sh - shared helpers, sourced by all other scripts
# Do not run this directly

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()  { echo -e "${BLUE}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }

# Project root = the directory this script lives in
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
ENV_FILE="$PROJECT_ROOT/.env"
ENV_EXAMPLE="$PROJECT_ROOT/.env.example"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.yml"

check_docker() {
    if ! command -v docker &> /dev/null; then
        err "Docker is not installed. Install it first: https://docs.docker.com/engine/install/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        err "Docker daemon is not running. Start it: sudo systemctl start docker"
        exit 1
    fi

    if ! docker compose version &> /dev/null; then
        err "'docker compose' (v2 plugin) not found. Please install Docker Compose v2."
        exit 1
    fi
}

check_compose_file() {
    if [ ! -f "$COMPOSE_FILE" ]; then
        err "docker-compose.yml not found at: $COMPOSE_FILE"
        exit 1
    fi
}

check_env_file() {
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f "$ENV_EXAMPLE" ]; then
            warn ".env not found, copying from .env.example..."
            cp "$ENV_EXAMPLE" "$ENV_FILE"
            warn ".env created with default values. Run './change.sh' if you need to set API keys/custom settings."
        else
            warn "Neither .env nor .env.example found. Docker Compose will run without .env (fine if not needed)."
        fi
    fi
}

dc() {
    # wrapper: always use the correct compose file and project root
    docker compose --project-directory "$PROJECT_ROOT" -f "$COMPOSE_FILE" "$@"
}
