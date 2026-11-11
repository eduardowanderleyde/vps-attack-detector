#!/bin/bash
# Sync logs from remote server
# Usage: ./sync_logs.sh [remote_host] [remote_user] [ssh_port]

set -e

REMOTE_HOST="${1:-${REMOTE_HOST}}"
REMOTE_USER="${2:-${REMOTE_USER:-root}}"
SSH_PORT="${3:-${REMOTE_SSH_PORT:-22}}"
SSH_KEY="${SSH_KEY_PATH:-~/.ssh/id_rsa}"
LOCAL_DIR="${LOCAL_LOG_PATH:-./data/logs_input}"

if [ -z "$REMOTE_HOST" ]; then
    echo "Usage: $0 <remote_host> [remote_user] [ssh_port]"
    echo "Or set REMOTE_HOST environment variable"
    exit 1
fi

mkdir -p "$LOCAL_DIR"

echo "Syncing logs from $REMOTE_USER@$REMOTE_HOST:$SSH_PORT..."

REMOTE_PATHS="${REMOTE_LOG_PATHS:-/var/log/auth.log,/var/log/nginx/access.log,/var/log/nginx/error.log}"

IFS=',' read -ra PATHS <<< "$REMOTE_PATHS"
for path in "${PATHS[@]}"; do
    path=$(echo "$path" | xargs)
    if [ -n "$path" ]; then
        echo "Syncing $path..."
        rsync -avz --timeout=60 \
            -e "ssh -p $SSH_PORT -i $SSH_KEY -o StrictHostKeyChecking=no" \
            "$REMOTE_USER@$REMOTE_HOST:$path" \
            "$LOCAL_DIR/" || echo "Warning: Failed to sync $path"
    fi
done

echo "Sync complete. Logs in $LOCAL_DIR"
