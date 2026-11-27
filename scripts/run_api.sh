#!/usr/bin/env bash
# Start the NDR API (REST + WebSocket + built dashboard) with uvicorn.
set -euo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD:${PYTHONPATH:-}"

HOST="${NDR_HOST:-0.0.0.0}"
PORT="${NDR_PORT:-8000}"

if [ ! -f frontend/dist/index.html ]; then
  echo "frontend/dist missing - building dashboard"
  (cd frontend && if [ -f package-lock.json ]; then npm ci --silent; else npm install --silent; fi && npm run build)
fi

exec uvicorn src.api.app:app --host "$HOST" --port "$PORT" "$@"
