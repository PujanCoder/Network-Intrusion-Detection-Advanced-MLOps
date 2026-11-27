from __future__ import annotations

from typing import Any

from ..schema import LogType, ZeekEventEnvelope, event_fingerprint, normalize_ts, utc_now_iso


LOG_TYPE_ALIASES = {
    "conn": "conn",
    "dns": "dns",
    "http": "http",
    "ssl": "ssl",
    "tls": "ssl",
    "files": "files",
    "notice": "notice",
}


def detect_log_type(source_file: str, record: dict[str, Any]) -> LogType:
    name = source_file.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for key, val in LOG_TYPE_ALIASES.items():
        if name == f"{key}.log" or name.startswith(f"{key}."):
            return val  # type: ignore[return-value]
    # Fallback heuristics
    if "conn_state" in record and "id.orig_h" in record:
        return "conn"
    if "query" in record and "qtype_name" in record:
        return "dns"
    if "method" in record and "uri" in record:
        return "http"
    if "server_name" in record and "cipher" in record:
        return "ssl"
    if "fuid" in record and "mime_type" in record:
        return "files"
    if "note" in record and "msg" in record:
        return "notice"
    return "unknown"


def _get(record: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in record:
            return record[k]
    return None


def _int_or_none(v: Any) -> int | None:
    if v is None or v == "-" or v == "":
        return None
    try:
        return int(v)
    except Exception:
        return None


def common_fields(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "uid": _get(record, "uid"),
        "src_ip": _get(record, "id.orig_h", "src_ip"),
        "src_port": _int_or_none(_get(record, "id.orig_p", "src_port")),
        "dst_ip": _get(record, "id.resp_h", "dst_ip"),
        "dst_port": _int_or_none(_get(record, "id.resp_p", "dst_port")),
        "proto": _get(record, "proto"),
        "service": _get(record, "service"),
    }


def normalize_record(
    *,
    record: dict[str, Any],
    source_file: str,
    source_offset: int,
    source_inode: str | None,
    sensor_id: str,
    log_type_hint: str | None = None,
) -> ZeekEventEnvelope:
    from .conn import normalize_conn
    from .dns import normalize_dns
    from .files import normalize_files
    from .http import normalize_http
    from .notice import normalize_notice
    from .ssl import normalize_ssl

    log_type = (log_type_hint or detect_log_type(source_file, record))  # type: ignore[assignment]
    if log_type == "tls":
        log_type = "ssl"
    normalizers = {
        "conn": normalize_conn,
        "dns": normalize_dns,
        "http": normalize_http,
        "ssl": normalize_ssl,
        "files": normalize_files,
        "notice": normalize_notice,
    }
    normalizer = normalizers.get(log_type)
    parse_errors: list[str] = []
    normalized: dict[str, Any] = {}
    parse_status = "ok"
    if normalizer:
        try:
            normalized = normalizer(record)
        except Exception as e:  # noqa: BLE001
            parse_status = "partial"
            parse_errors.append(f"normalizer error: {e}")
            normalized = {"_raw_keys": list(record.keys())}
    else:
        parse_status = "partial"
        parse_errors.append(f"unsupported log_type: {log_type}")
        normalized = {"_raw_keys": list(record.keys())}

    common = common_fields(record)
    ts = normalize_ts(record.get("ts"))
    event_id = event_fingerprint(
        sensor_id=sensor_id,
        log_type=log_type,
        ts=ts,
        uid=common.get("uid"),
        source_file=source_file,
        source_offset=source_offset,
        raw=record,
    )
    return ZeekEventEnvelope(
        event_id=event_id,
        log_type=log_type if log_type in {"conn", "dns", "http", "ssl", "files", "notice"} else "unknown",
        ts=ts,
        ingested_at=utc_now_iso(),
        sensor_id=sensor_id,
        uid=common.get("uid"),
        src_ip=common.get("src_ip"),
        src_port=common.get("src_port"),
        dst_ip=common.get("dst_ip"),
        dst_port=common.get("dst_port"),
        proto=common.get("proto"),
        service=common.get("service"),
        severity=normalized.get("severity"),
        raw=record,
        normalized=normalized,
        parse_status=parse_status,
        parse_errors=parse_errors,
        source_file=source_file,
        source_offset=source_offset,
        source_inode=source_inode,
    )
