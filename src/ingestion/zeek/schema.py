from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


LogType = Literal["conn", "dns", "http", "ssl", "files", "notice", "unknown"]
ParseStatus = Literal["ok", "partial", "quarantined"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_ts(value: Any) -> str:
    """Normalize Zeek ts (epoch float/int or ISO string) to UTC ISO8601."""
    if value is None:
        return utc_now_iso()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return utc_now_iso()
        # Zeek JSON usually gives epoch seconds; sometimes ISO strings appear in fixtures.
        try:
            return datetime.fromtimestamp(float(raw), tz=timezone.utc).isoformat()
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            return utc_now_iso()
    return utc_now_iso()


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def event_fingerprint(
    *,
    sensor_id: str,
    log_type: str,
    ts: str,
    uid: str | None,
    source_file: str,
    source_offset: int,
    raw: dict[str, Any],
) -> str:
    """Deterministic semantic fingerprint for idempotent ingestion.

    source_file/source_offset are kept in the function signature for call-site
    compatibility and traceability, but the fingerprint is based on semantic
    event content so replay/copies are deduplicated.
    """
    base = "|".join(
        [
            sensor_id,
            log_type,
            ts,
            uid or "",
            canonical_json(raw),
        ]
    )
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


class ZeekEventEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    source: Literal["zeek"] = "zeek"
    log_type: LogType
    ts: str
    ingested_at: str
    sensor_id: str
    uid: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    proto: str | None = None
    service: str | None = None
    severity: str | None = None
    raw: dict[str, Any]
    normalized: dict[str, Any] = Field(default_factory=dict)
    parse_status: ParseStatus = "ok"
    parse_errors: list[str] = Field(default_factory=list)
    source_file: str
    source_offset: int
    source_inode: str | None = None


class ZeekDeadLetter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str
    source_file: str
    source_offset: int
    source_inode: str | None = None
    error: str
    raw_line: str
    created_at: str
