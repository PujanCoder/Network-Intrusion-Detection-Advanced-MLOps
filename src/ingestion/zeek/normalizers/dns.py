from __future__ import annotations

from typing import Any


def _int(v: Any):
    if v is None or v == "-":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _float(v: Any):
    if v is None or v == "-":
        return None
    try:
        return float(v)
    except Exception:
        return None


def normalize_dns(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "query": r.get("query"),
        "qclass_name": r.get("qclass_name"),
        "qtype_name": r.get("qtype_name"),
        "rcode_name": r.get("rcode_name"),
        "AA": r.get("AA"),
        "TC": r.get("TC"),
        "RD": r.get("RD"),
        "RA": r.get("RA"),
        "rejected": r.get("rejected"),
        "answers": r.get("answers"),
        "TTLs": r.get("TTLs"),
        "rtt": _float(r.get("rtt")),
        "trans_id": _int(r.get("trans_id")),
    }
