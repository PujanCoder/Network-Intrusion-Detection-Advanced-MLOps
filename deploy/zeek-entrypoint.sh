#!/bin/sh
# Start Zeek in JSON mode and write its logs to the shared volume that the
# NDR ingestion service tails. Override SENSOR_INTERFACE to capture elsewhere.
set -eu

: "${SENSOR_INTERFACE:=eth0}"
: "${NDR_ZEEK_LOG_DIR:=/var/log/zeek}"

mkdir -p "$NDR_ZEEK_LOG_DIR"
cd "$NDR_ZEEK_LOG_DIR"

exec zeek LogAscii::use_json=T -i "$SENSOR_INTERFACE" "$@"
