from __future__ import annotations

from typing import Any


def normalize_notice(r: dict[str, Any]) -> dict[str, Any]:
    note = r.get("note")
    severity = "high" if note else None
    return {
        "note": note,
        "msg": r.get("msg"),
        "sub": r.get("sub"),
        "src": r.get("src"),
        "dst": r.get("dst"),
        "p": r.get("p"),
        "n": r.get("n"),
        "peer_descr": r.get("peer_descr"),
        "actions": r.get("actions"),
        "suppress_for": r.get("suppress_for"),
        "severity": severity,
    }
