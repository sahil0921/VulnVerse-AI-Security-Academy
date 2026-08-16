#!/usr/bin/env bash
# clean.sh - PERMANENT cleanup. Deletes containers + volumes + images.
# Frees up disk space. After this, run './setup.sh' again to rebuild.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "⚠ This action is PERMANENT. It will delete:"
echo "    - All containers"
echo "    - All volumes (lab data, DB, uploaded files - EVERYTHING)"
echo "    - All images (you'll need to rebuild on next setup)"
echo
read -r -p "Are you sure? Type 'yes' to confirm: " CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo "Cancelled. Nothing was deleted."
    exit 0
fi

echo
echo "Cleaning up everything..."
docker compose down -v --rmi all --remove-orphans

echo
echo "✅ Fully cleaned up. Disk space has been freed."
echo "Run './setup.sh' if you want to use it again."
