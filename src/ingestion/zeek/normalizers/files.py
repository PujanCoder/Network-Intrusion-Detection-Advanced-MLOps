from __future__ import annotations

from typing import Any


def _int(v: Any):
    if v is None or v == "-":
        return None
    try:
        return int(v)
    except Exception:
        return None


def normalize_files(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "fuid": r.get("fuid"),
        "tx_hosts": r.get("tx_hosts"),
        "rx_hosts": r.get("rx_hosts"),
        "conn_uids": r.get("conn_uids"),
        "source": r.get("source"),
        "depth": _int(r.get("depth")),
        "analyzers": r.get("analyzers"),
        "mime_type": r.get("mime_type"),
        "filename": r.get("filename"),
        "duration": r.get("duration"),
        "local_orig": r.get("local_orig"),
        "is_orig": r.get("is_orig"),
        "seen_bytes": _int(r.get("seen_bytes")),
        "total_bytes": _int(r.get("total_bytes")),
        "missing_bytes": _int(r.get("missing_bytes")),
        "md5": r.get("md5"),
        "sha1": r.get("sha1"),
        "sha256": r.get("sha256"),
    }
