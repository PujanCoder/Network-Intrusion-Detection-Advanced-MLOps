from __future__ import annotations

from typing import Any


def _int(v: Any):
    if v is None or v == "-":
        return None
    try:
        return int(v)
    except Exception:
        return None


def normalize_http(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": r.get("method"),
        "host": r.get("host"),
        "uri": r.get("uri"),
        "referrer": r.get("referrer"),
        "user_agent": r.get("user_agent"),
        "status_code": _int(r.get("status_code")),
        "status_msg": r.get("status_msg"),
        "request_body_len": _int(r.get("request_body_len")),
        "response_body_len": _int(r.get("response_body_len")),
        "resp_mime_types": r.get("resp_mime_types"),
        "orig_mime_types": r.get("orig_mime_types"),
        "version": r.get("version"),
    }
