#!/usr/bin/env bash
# stop.sh - Stops containers WITHOUT deleting them.
# Data/volumes stay safe. Use './resume.sh' to turn it back on.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

echo "=========================================="
echo "   VulnVerse - Stopping Lab"
echo "=========================================="
echo ""

check_docker
check_compose_file

info "Stopping containers (data will stay safe)..."
dc stop

echo ""
ok "Lab stopped. Run './resume.sh' to start it again."
