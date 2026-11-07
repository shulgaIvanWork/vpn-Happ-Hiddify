#!/usr/bin/env bash
# Bootstrap the aggregator on a fresh Debian/Ubuntu VPS.
# Usage: DOMAIN=vpn.example.com bash scripts/server_bootstrap.sh
set -euo pipefail

REPO="${REPO:-https://github.com/shulgaIvanWork/vpn-Happ-Hiddify.git}"
DIR="${DIR:-/opt/my-vpn}"
DOMAIN="${DOMAIN:-}"

log() { echo "==> $*"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

if ! command -v apt-get >/dev/null 2>&1; then
  echo "Only apt-based systems are supported" >&2
  exit 1
fi

log "Installing base packages"
apt-get update -y
apt-get install -y ca-certificates curl git openssl

if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker"
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  sh /tmp/get-docker.sh
fi

systemctl enable --now docker

if [ -d "$DIR/.git" ]; then
  log "Updating $DIR"
  git -C "$DIR" fetch --all --prune
  git -C "$DIR" reset --hard origin/main
else
  log "Cloning into $DIR"
  mkdir -p "$(dirname "$DIR")"
  git clone "$REPO" "$DIR"
fi

cd "$DIR"

if [ ! -f .env ]; then
  log "Creating .env"
  SUB_TOKEN="$(openssl rand -hex 24)"
  ADMIN_TOKEN="$(openssl rand -hex 24)"
  cat > .env <<EOF
DOMAIN=${DOMAIN}
BIND_ADDR=127.0.0.1
SUB_TOKEN=${SUB_TOKEN}
ADMIN_TOKEN=${ADMIN_TOKEN}
PROFILE_TITLE=Moscow Auto-VPN
SUPPORT_URL=https://t.me/your_channel
TOTAL_BYTES=322122547200
EXPIRE_UNIX=1893456000
NODES_IN_SUB=35
MAX_NODES_PER_SUBNET=8
BATCH_SIZE=70
CHECK_TIMEOUT=4
PROBE_CONCURRENCY=20
PORT_BASE=20000
PORT_BAND=3000
MAX_NODES_PER_SCAN=1500
MAX_LATENCY_MS=8000
FULL_SCAN_INTERVAL=3600
LIVE_RECHECK_INTERVAL=600
LOG_LEVEL=INFO
TRUST_FORWARDED_FOR=true
RATE_LIMIT_PER_MIN=120
EOF
  chmod 600 .env
fi

mkdir -p data
chown -R 10001:10001 data

log "Starting containers"
if [ -n "$DOMAIN" ]; then
  docker compose --profile edge up -d --build
else
  docker compose up -d --build
fi

log "Waiting for health"
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

curl -sS http://127.0.0.1:8000/healthz || true
echo
docker compose ps

if [ -f .env ]; then
  # shellcheck disable=SC1091
  . ./.env
  echo
  echo "Local subscription: http://127.0.0.1:8000/sub/${SUB_TOKEN}"
  echo "Admin token: see ${DIR}/.env"
fi
