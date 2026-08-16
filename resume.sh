#!/usr/bin/env bash
# resume.sh - Turns existing containers back ON.
# Uses 'docker compose up -d' (not just 'start') so that if .env changed
# (via change.sh) or a container is missing, it fixes itself automatically.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

echo "=========================================="
echo "   VulnVerse - Resuming Lab"
echo "=========================================="
echo ""

check_docker
check_compose_file

# If setup was never run (no images/containers built), tell the user
if [ -z "$(dc images -q 2>/dev/null)" ]; then
    err "Looks like setup hasn't been run yet. Run './setup.sh' first."
    exit 1
fi

info "Starting/updating containers..."
dc up -d

echo ""
dc ps

echo ""
ok "Lab is back ON!"
echo "  -> Dashboard: http://localhost:8080"
