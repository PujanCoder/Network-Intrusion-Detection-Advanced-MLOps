from __future__ import annotations

from typing import Any


def normalize_ssl(r: dict[str, Any]) -> dict[str, Any]:
    return {
        "server_name": r.get("server_name"),
        "version": r.get("version"),
        "cipher": r.get("cipher"),
        "curve": r.get("curve"),
        "resumed": r.get("resumed"),
        "established": r.get("established"),
        "last_alert": r.get("last_alert"),
        "next_protocol": r.get("next_protocol"),
        "validation_status": r.get("validation_status"),
        "cert_chain_fps": r.get("cert_chain_fps"),
        "ja3": r.get("ja3"),
        "ja3s": r.get("ja3s"),
    }
