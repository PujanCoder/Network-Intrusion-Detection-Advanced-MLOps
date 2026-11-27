#!/usr/bin/env bash
# Run Zeek with JSON logs in the directory the ingestion service watches.
#
#   sudo ./scripts/zeek_live.sh -i eth0          # live capture
#   ./scripts/zeek_live.sh -r capture.pcap       # replay a PCAP
#
# Zeek must be installed (https://docs.zeek.org/en/master/install.html).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v zeek >/dev/null 2>&1; then
  echo "zeek not found on PATH. Install Zeek or use scripts/replay_zeek_holdout.py." >&2
  exit 1
fi

LOG_DIR="${NDR_ZEEK_LOG_DIR:-data/zeek_logs}"
mkdir -p "$LOG_DIR"
cd "$LOG_DIR"
exec zeek LogAscii::use_json=T "$@"
