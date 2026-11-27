from __future__ import annotations

from .schema import canonical_json, event_fingerprint


def fingerprint_event(*, sensor_id: str, log_type: str, ts: str, uid: str | None, source_file: str, source_offset: int, raw: dict) -> str:
    return event_fingerprint(
        sensor_id=sensor_id,
        log_type=log_type,
        ts=ts,
        uid=uid,
        source_file=source_file,
        source_offset=source_offset,
        raw=raw,
    )


__all__ = ["fingerprint_event", "canonical_json"]
