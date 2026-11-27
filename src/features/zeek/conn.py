from __future__ import annotations

import math
from typing import Any

# Zeek conn.log-native baseline features. This schema is intentionally separate
# from CICIDS2017 feature_order and must not be fed into the CICIDS model.
CONN_FEATURE_NAMES = [
    "duration",
    "orig_bytes",
    "resp_bytes",
    "missed_bytes",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "service_dns",
    "service_http",
    "service_ssl",
    "service_ssh",
    "service_other",
    "conn_state_SF",
    "conn_state_S0",
    "conn_state_REJ",
    "conn_state_RSTO",
    "conn_state_other",
    "bytes_ratio",
    "pkts_ratio",
    "bytes_per_pkt_orig",
    "bytes_per_pkt_resp",
]


def _f(v: Any, default: float = 0.0) -> float:
    if v is None or v == "-" or v == "":
        return default
    try:
        x = float(v)
        if math.isnan(x) or math.isinf(x):
            return default
        return x
    except Exception:
        return default


def extract_conn_features(normalized: dict[str, Any], *, proto: str | None = None, service: str | None = None) -> dict[str, float]:
    proto = (proto or "").lower()
    service = (service or "").lower()
    conn_state = str(normalized.get("conn_state") or "")

    orig_bytes = _f(normalized.get("orig_bytes"))
    resp_bytes = _f(normalized.get("resp_bytes"))
    orig_pkts = _f(normalized.get("orig_pkts"))
    resp_pkts = _f(normalized.get("resp_pkts"))
    orig_ip = _f(normalized.get("orig_ip_bytes"))
    resp_ip = _f(normalized.get("resp_ip_bytes"))

    feat = {
        "duration": _f(normalized.get("duration")),
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "missed_bytes": _f(normalized.get("missed_bytes")),
        "orig_pkts": orig_pkts,
        "orig_ip_bytes": orig_ip,
        "resp_pkts": resp_pkts,
        "resp_ip_bytes": resp_ip,
        "proto_tcp": 1.0 if proto == "tcp" else 0.0,
        "proto_udp": 1.0 if proto == "udp" else 0.0,
        "proto_icmp": 1.0 if proto == "icmp" else 0.0,
        "service_dns": 1.0 if service == "dns" else 0.0,
        "service_http": 1.0 if service == "http" else 0.0,
        "service_ssl": 1.0 if service in ("ssl", "tls") else 0.0,
        "service_ssh": 1.0 if service == "ssh" else 0.0,
        "service_other": 1.0 if service and service not in {"dns", "http", "ssl", "tls", "ssh"} else 0.0,
        "conn_state_SF": 1.0 if conn_state == "SF" else 0.0,
        "conn_state_S0": 1.0 if conn_state == "S0" else 0.0,
        "conn_state_REJ": 1.0 if conn_state == "REJ" else 0.0,
        "conn_state_RSTO": 1.0 if conn_state in {"RSTO", "RSTR", "RSTOS0", "RSTRH"} else 0.0,
        "conn_state_other": 1.0 if conn_state and conn_state not in {"SF", "S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH"} else 0.0,
        "bytes_ratio": orig_bytes / (resp_bytes + 1.0),
        "pkts_ratio": orig_pkts / (resp_pkts + 1.0),
        "bytes_per_pkt_orig": orig_ip / (orig_pkts + 1.0),
        "bytes_per_pkt_resp": resp_ip / (resp_pkts + 1.0),
    }
    # ensure stable order keys exist
    return {k: float(feat.get(k, 0.0)) for k in CONN_FEATURE_NAMES}
