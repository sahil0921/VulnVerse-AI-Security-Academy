#!/usr/bin/env bash
# status.sh - Shows which containers are running + disk usage.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

docker compose ps
echo
echo "Docker disk usage:"
docker system df
