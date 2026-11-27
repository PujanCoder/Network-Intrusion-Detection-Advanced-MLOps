#!/usr/bin/env python3
"""Forward Zeek logs from a local sensor to a hosted NDR API over HTTPS.

The hosted deployment cannot read logs from your network, so this small agent
tails a Zeek log on the sensor host and pushes new records to
``POST /api/ingest/zeek``. It keeps a byte offset on disk, so restarts resume
where they stopped and nothing is sent twice (the API also de-duplicates by
event uid).

Typical use on the sensor machine::

    export NDR_API_KEY=...            # the same key the Render service uses
    python scripts/zeek_forward.py \
        --url https://ndr-platform.onrender.com \
        --log /opt/zeek/logs/current/conn.log \
        --follow

Zeek must write JSON for this to work::

    echo 'redef LogAscii::use_json = T;' >> /opt/zeek/share/zeek/site/local.zeek

TSV logs with a ``#fields`` header are also accepted.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.realtime.zeek_parser import ZeekLogParser  # noqa: E402

logger = logging.getLogger("zeek-forward")

DEFAULT_BATCH = 200


def _read_batch(handle, parser: ZeekLogParser, source: str, limit: int) -> list[dict]:
    """Read complete lines from the current offset, stopping at a partial line."""

    records: list[dict] = []
    while len(records) < limit:
        position = handle.tell()
        line = handle.readline()
        if not line:
            handle.seek(position)
            break
        if not line.endswith("\n"):
            # Partial write from Zeek: rewind and retry on the next pass.
            handle.seek(position)
            break
        # JSON lines win over the TSV header state: a file can carry a #fields
        # header from a previous non-JSON config and still be JSON afterwards.
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                parsed = None
            record = parsed if isinstance(parsed, dict) else None
        else:
            record = parser.parse_line(source, line)
        if record is not None:
            records.append(record)
    return records


def _post(url: str, api_key: str, payload: dict, insecure: bool, timeout: float = 30.0) -> dict:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    request = urllib.request.Request(
        url.rstrip("/") + "/api/ingest/zeek",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-API-Key": api_key},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.loads(response.read().decode("utf-8"))


def _load_offset(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("Ignoring unreadable state file %s", path)
        return {}


def _save_offset(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state), encoding="utf-8")
    tmp.replace(path)


def forward_once(args: argparse.Namespace) -> dict:
    log_path = Path(args.log).expanduser()
    if not log_path.exists():
        raise SystemExit(f"log file not found: {log_path}")

    state_path = Path(args.state).expanduser()
    state = _load_offset(state_path)
    key = str(log_path.resolve())
    offset = int(state.get(key, 0))
    size = log_path.stat().st_size
    if offset > size:
        logger.warning("%s shrank; restarting from the beginning", log_path.name)
        offset = 0

    parser = ZeekLogParser()
    sent = 0
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        while True:
            records = _read_batch(handle, parser, f"remote:{args.sensor_id}:{args.log_type}.log", args.batch)
            if not records:
                break
            result = _post(
                args.url,
                args.api_key,
                {"sensor_id": args.sensor_id, "log_type": args.log_type, "records": records},
                args.insecure,
            )
            sent += len(records)
            logger.info(
                "pushed %s records: inserted=%s duplicates=%s predictions=%s alerts=%s rejected=%s",
                len(records),
                result.get("inserted"),
                result.get("duplicates"),
                result.get("predictions"),
                result.get("alerts"),
                result.get("rejected"),
            )
            offset = handle.tell()
            state[key] = offset
            _save_offset(state_path, state)

    return {"sent": sent, "offset": offset}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forward Zeek logs to a hosted NDR API")
    parser.add_argument("--url", required=True, help="Base URL, e.g. https://ndr.onrender.com")
    parser.add_argument("--log", required=True, help="Path to a Zeek log (conn.log, dns.log, ...)")
    parser.add_argument("--log-type", default="conn", help="Zeek log type (default: conn)")
    parser.add_argument("--sensor-id", default=os.getenv("NDR_SENSOR_ID", "local-zeek"))
    parser.add_argument("--state", default="~/.ndr-forward-state.json", help="Offset state file")
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH, help="Records per request")
    parser.add_argument("--interval", type=float, default=2.0, help="Poll interval in --follow mode")
    parser.add_argument("--follow", action="store_true", help="Keep tailing the file")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS verification (testing only)")
    parser.add_argument("--api-key", default=os.getenv("NDR_API_KEY"), help="Defaults to $NDR_API_KEY")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if not args.api_key:
        parser.error("an API key is required: pass --api-key or set NDR_API_KEY")
    if not args.url.startswith("https://") and not args.insecure:
        parser.error("refusing to send events over plain HTTP; use https:// or --insecure for a lab")

    try:
        while True:
            summary = forward_once(args)
            if not args.follow:
                logger.info("forwarded %s records (offset %s)", summary["sent"], summary["offset"])
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", "replace")[:200]
        logger.error("API rejected the batch (%s): %s", error.code, body)
        return 2
    except urllib.error.URLError as error:
        logger.error("cannot reach %s: %s", args.url, error.reason)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
