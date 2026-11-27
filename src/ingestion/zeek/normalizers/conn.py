from __future__ import annotations

from typing import Any


def _num(v: Any):
    if v is None or v == "-":
        return None
    try:
        return float(v)
    except Exception:
        return None


def _int(v: Any):
    if v is None or v == "-":
        return None
    try:
        return int(v)
    except Exception:
        return None


def normalize_conn(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "duration": _num(r.get("duration")),
        "orig_bytes": _int(r.get("orig_bytes")),
        "resp_bytes": _int(r.get("resp_bytes")),
        "missed_bytes": _int(r.get("missed_bytes")),
        "conn_state": r.get("conn_state"),
        "history": r.get("history"),
        "orig_pkts": _int(r.get("orig_pkts")),
        "orig_ip_bytes": _int(r.get("orig_ip_bytes")),
        "resp_pkts": _int(r.get("resp_pkts")),
        "resp_ip_bytes": _int(r.get("resp_ip_bytes")),
        "local_orig": r.get("local_orig"),
        "local_resp": r.get("local_resp"),
        "tunnel_parents": r.get("tunnel_parents"),
    }
