#!/usr/bin/env python3
"""Replay held-out labelled flows as a Zeek-shaped ``conn.log``.

This is an offline replay harness, not a traffic generator. It reads flows from
``data/processed/zeek_holdout/cicids_holdout.csv`` that were held out from model
training and appends them, one JSON record at a time, to a log file. The normal
ingestion path (incremental reader -> parser -> features -> model -> SQLite ->
WebSocket) processes them exactly as it processes live Zeek output.

Use it to demo the dashboard when no live sensor is attached::

    python scripts/replay_zeek_holdout.py --rate 6 --count 400

Set ``NDR_SENSOR_MODE=replay`` (the default in ``.env.example``) so the UI shows
that the source is a replay, never live traffic.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import random
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.realtime.config import PROJECT_ROOT as ROOT, get_settings  # noqa: E402

DEFAULT_INPUT = ROOT / "data" / "processed" / "zeek_holdout" / "cicids_holdout.csv"

# Representative ports per destination-port class used by the feature schema.
PORT_FOR_CLASS = {1: 443, 2: 21, 3: 22, 4: 25, 5: 3306, 6: 53, 7: 123, 8: 49152}
STATE_FOR_CODE = {
    1: "SF", 2: "S0", 3: "REJ", 4: "RSTO", 5: "RSTR",
    6: "S1", 7: "SH", 8: "S2", 9: "S3", 10: "RSTOS0", 11: "OTH",
}
PROTO_FOR_CODE = {1: "tcp", 2: "udp", 3: "icmp"}

ATTACKER_POOL = [f"203.0.113.{i}" for i in (7, 19, 44, 88)]
SERVER_POOL = ["10.20.0.10", "10.20.0.11", "10.20.0.20", "10.20.0.31", "10.20.0.42"]


def stable_choice(pool: list[str], key: str) -> str:
    digest = hashlib.sha256(key.encode()).hexdigest()
    return pool[int(digest[:8], 16) % len(pool)]


def build_record(row: dict[str, str], index: int, now: float, rng: random.Random) -> dict:
    label = row.get("label", "BENIGN")
    malicious = label != "BENIGN"

    src_ip = stable_choice(ATTACKER_POOL, f"{label}-{index}") if malicious else str(
        ipaddress.ip_address("10.30.0.0") + (int(hashlib.sha256(f"{index}".encode()).hexdigest()[:6], 16) % 60000)
    )
    dst_ip = stable_choice(SERVER_POOL, f"dst-{index}")

    port_class = int(float(row.get("dst_port_class") or 8))
    dst_port = PORT_FOR_CLASS.get(port_class, 49152)
    if port_class == 8:
        dst_port = 1024 + (index * 37) % 60000
    src_port = rng.randint(32768, 60999)

    state_code = int(float(row.get("conn_state_code") or 1))
    proto = PROTO_FOR_CODE.get(int(float(row.get("proto_code") or 1)), "tcp")

    def number(key: str) -> float:
        value = row.get(key)
        try:
            return float(value) if value not in (None, "", "nan") else 0.0
        except ValueError:
            return 0.0

    return {
        "ts": round(now, 6),
        "uid": f"C{int(now * 1e6) % 10**12:x}{index:x}",
        "id.orig_h": src_ip,
        "id.orig_p": src_port,
        "id.resp_h": dst_ip,
        "id.resp_p": dst_port,
        "proto": proto,
        "service": "ssl" if dst_port == 443 else ("http" if dst_port == 80 else "-"),
        "duration": round(number("duration_s"), 6),
        "orig_bytes": int(number("orig_bytes")),
        "resp_bytes": int(number("resp_bytes")),
        "conn_state": STATE_FOR_CODE.get(state_code, "SF"),
        "local_orig": True,
        "local_resp": False,
        "missed_bytes": 0,
        "history": "ShADadFf" if state_code == 1 else "S",
        "orig_pkts": int(number("orig_pkts")),
        "orig_ip_bytes": int(number("orig_ip_bytes")),
        "resp_pkts": int(number("resp_pkts")),
        "resp_ip_bytes": int(number("resp_ip_bytes")),
        "tunnel_parents": [],
        "_replay": True,
        "_replay_label": label,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="held-out flow CSV")
    parser.add_argument("--log-dir", type=Path, default=get_settings().zeek_log_dir, help="directory holding conn.log")
    parser.add_argument("--log-name", default="conn.log", help="log file name")
    parser.add_argument("--rate", type=float, default=5.0, help="records per second")
    parser.add_argument("--count", type=int, default=0, help="stop after N records (0 = whole file)")
    parser.add_argument("--loop", action="store_true", help="restart from the top when the file ends")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args(argv)

    if not args.input.exists():
        print(f"replay input missing: {args.input}\nRun training first: python -m src.realtime.training", file=sys.stderr)
        return 2

    with args.input.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        print("replay input is empty", file=sys.stderr)
        return 2

    args.log_dir.mkdir(parents=True, exist_ok=True)
    log_path = args.log_dir / args.log_name
    rng = random.Random(args.seed)
    interval = 1.0 / args.rate if args.rate > 0 else 0.0

    print(f"replaying {len(rows)} held-out flows -> {log_path} at {args.rate}/s", flush=True)
    written = 0
    with log_path.open("a", encoding="utf-8") as sink:
        while True:
            for index, row in enumerate(rows):
                record = build_record(row, written, time.time(), rng)
                sink.write(json.dumps(record) + "\n")
                sink.flush()
                written += 1
                if written % 25 == 0:
                    print(f"  {written} records written", flush=True)
                if args.count and written >= args.count:
                    print(f"done: {written} records", flush=True)
                    return 0
                time.sleep(interval)
            if not args.loop:
                break
    print(f"done: {written} records", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
