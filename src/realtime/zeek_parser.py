"""Zeek log parsing and normalization.

Supports both of Zeek's ASCII outputs:

* JSON  (``LogAscii::use_json=T``) -- one JSON object per line.
* TSV   (Zeek default) -- ``#separator`` / ``#fields`` / ``#types`` headers.

Only fields that are actually present in a log are used; nothing is invented.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SUPPORTED_LOG_TYPES = (
    "conn",
    "dns",
    "http",
    "ssl",
    "files",
    "notice",
    "weird",
    "x509",
    "dhcp",
    "smtp",
    "ssh",
    "ftp",
    "syslog",
    "tunnel",
    "capture_loss",
)

_UNSET = {"-", "(empty)", ""}


def log_type_for_path(path: Path | str) -> str:
    """``conn.log`` / ``conn.2024-01-01-00-00-00.log.gz`` -> ``conn``."""

    name = Path(path).name
    return name.split(".", 1)[0]


def _clean(value: Any) -> Any:
    if isinstance(value, str):
        stripped = value.strip()
        if stripped in _UNSET:
            return None
        return stripped
    return value


def _to_float(value: Any) -> float | None:
    value = _clean(value)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _to_int(value: Any) -> int | None:
    value = _clean(value)
    if value is None:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


@dataclass
class NormalizedEvent:
    """A log-type-agnostic view of a Zeek record."""

    event_uid: str
    ts: float
    log_type: str
    sensor: str
    source_file: str
    source_offset: int
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    proto: str | None = None
    service: str | None = None
    conn_state: str | None = None
    duration: float | None = None
    orig_bytes: int | None = None
    resp_bytes: int | None = None
    orig_pkts: int | None = None
    resp_pkts: int | None = None
    orig_ip_bytes: int | None = None
    resp_ip_bytes: int | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> dict[str, Any]:
        return {
            "event_uid": self.event_uid,
            "ts": self.ts,
            "log_type": self.log_type,
            "sensor": self.sensor,
            "source_file": self.source_file,
            "source_offset": self.source_offset,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "service": self.service,
            "conn_state": self.conn_state,
            "duration": self.duration,
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "orig_pkts": self.orig_pkts,
            "resp_pkts": self.resp_pkts,
            "orig_ip_bytes": self.orig_ip_bytes,
            "resp_ip_bytes": self.resp_ip_bytes,
            "raw_json": json.dumps(self.raw, separators=(",", ":"), default=str),
        }


class ZeekLogParser:
    """Stateful line parser.

    The TSV branch needs the ``#fields`` header of each file, which is why the
    parser keeps per-file header state. JSON logs need no state.
    """

    def __init__(self) -> None:
        self._fields: dict[str, list[str]] = {}
        self._separator: dict[str, str] = {}
        self._json: dict[str, bool] = {}

    # ------------------------------------------------------------------ #
    # line level
    # ------------------------------------------------------------------ #
    def parse_line(self, source_file: str, line: str) -> dict[str, Any] | None:
        line = line.rstrip("\r\n")
        if not line:
            return None

        if line.startswith("#"):
            self._parse_header(source_file, line)
            return None

        if self._json.get(source_file, line.startswith("{")):
            self._json[source_file] = True
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return None
            return record if isinstance(record, dict) else None

        fields = self._fields.get(source_file)
        if not fields:
            # A TSV line without a header cannot be interpreted safely.
            return None
        separator = self._separator.get(source_file, "\t")
        values = line.split(separator)
        if len(values) != len(fields):
            return None
        return dict(zip(fields, values))

    def _parse_header(self, source_file: str, line: str) -> None:
        if line.startswith("#separator"):
            raw = line[len("#separator"):].strip()
            if raw == "\\x09":
                self._separator[source_file] = "\t"
            elif raw:
                self._separator[source_file] = raw
        elif line.startswith("#fields"):
            self._fields[source_file] = line.split("\t")[1:]
            self._json[source_file] = False
        elif line.startswith("#close"):
            self._fields.pop(source_file, None)
            self._json.pop(source_file, None)

    # ------------------------------------------------------------------ #
    # record level
    # ------------------------------------------------------------------ #
    def normalize(
        self,
        record: dict[str, Any],
        log_type: str,
        sensor: str,
        source_file: str,
        source_offset: int = 0,
    ) -> NormalizedEvent | None:
        ts = _to_float(record.get("ts"))
        if ts is None:
            return None

        src_ip = _clean(record.get("id.orig_h") or record.get("src"))
        dst_ip = _clean(record.get("id.resp_h") or record.get("dst"))
        src_port = _to_int(record.get("id.orig_p") or record.get("sport"))
        dst_port = _to_int(record.get("id.resp_p") or record.get("dport"))
        proto = _clean(record.get("proto"))
        uid = _clean(record.get("uid"))

        event = NormalizedEvent(
            event_uid="",
            ts=ts,
            log_type=log_type,
            sensor=sensor,
            source_file=source_file,
            source_offset=source_offset,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            proto=proto.lower() if isinstance(proto, str) else proto,
            service=_clean(record.get("service")),
            conn_state=_clean(record.get("conn_state")),
            duration=_to_float(record.get("duration")),
            orig_bytes=_to_int(record.get("orig_bytes")),
            resp_bytes=_to_int(record.get("resp_bytes")),
            orig_pkts=_to_int(record.get("orig_pkts")),
            resp_pkts=_to_int(record.get("resp_pkts")),
            orig_ip_bytes=_to_int(record.get("orig_ip_bytes")),
            resp_ip_bytes=_to_int(record.get("resp_ip_bytes")),
            raw=record,
        )
        event.event_uid = build_event_uid(event, uid)
        return event


def build_event_uid(event: NormalizedEvent, uid: str | None = None) -> str:
    """Stable identity used for duplicate prevention.

    Zeek's ``uid`` is the canonical connection identifier. When it is absent
    (dns/http logs without uid, or custom feeds) a deterministic hash of the
    identifying fields is used instead, so replaying a file twice never
    produces duplicate rows.
    """

    if uid:
        return f"{event.sensor}:{event.log_type}:{uid}"

    payload = "|".join(
        str(part)
        for part in (
            event.log_type,
            f"{event.ts:.6f}",
            event.src_ip,
            event.src_port,
            event.dst_ip,
            event.dst_port,
            event.proto,
            event.orig_bytes,
            event.resp_bytes,
            event.orig_pkts,
            event.resp_pkts,
            event.raw.get("query") or event.raw.get("host") or "",
        )
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
    return f"{event.sensor}:{event.log_type}:{digest}"


def iter_records(
    path: Path,
    start_offset: int = 0,
    sensor: str = "zeek-sensor-01",
) -> Iterator[tuple[int, NormalizedEvent]]:
    """Yield ``(line_offset, event)`` for every parseable record in ``path``.

    A trailing partial line (no newline yet, i.e. still being written by Zeek)
    is not consumed. Callers that tail files use the same rule.
    """

    log_type = log_type_for_path(path)
    parser = ZeekLogParser()
    with path.open("rb") as handle:
        handle.seek(start_offset)
        offset = start_offset
        for raw_line in handle:
            if not raw_line.endswith(b"\n"):
                break
            line_offset = offset
            offset += len(raw_line)
            line = raw_line.decode("utf-8", errors="replace")
            record = parser.parse_line(str(path), line)
            if record is None:
                continue
            event = parser.normalize(record, log_type, sensor, str(path), line_offset)
            if event is not None:
                yield line_offset, event


def iso_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")
