#!/usr/bin/env bash
set -euo pipefail

HOST="${1:?usage: ./scripts/deploy_moscow.sh user@host [remote_dir]}"
REMOTE_DIR="${2:-/opt/my-vpn}"

echo "==> Uploading to ${HOST}:${REMOTE_DIR}"
rsync -av --delete \
  --exclude '.venv' \
  --exclude 'bin' \
  --exclude 'data' \
  --exclude '.git' \
  --exclude '.env' \
  --exclude '__pycache__' \
  --exclude '.pytest_cache' \
  ./ "${HOST}:${REMOTE_DIR}/"

echo "==> Building and starting"
ssh "${HOST}" "cd '${REMOTE_DIR}' && mkdir -p data && chown -R 10001:10001 data && docker compose --profile edge up -d --build"

echo "==> Health"
ssh "${HOST}" "curl -fsS http://127.0.0.1:8000/healthz || true"
