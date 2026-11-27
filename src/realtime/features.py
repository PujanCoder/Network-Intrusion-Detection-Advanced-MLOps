"""Canonical feature schema shared by training and inference.

The same functions build vectors for:

* Zeek ``conn.log`` records (live inference),
* CICIDS2017 flow CSV rows,
* UNSW-NB15 flow rows,
* NSL-KDD connection records.

Sharing one implementation is what prevents train/serve skew. Where a source
does not provide a field the value is ``None`` (NaN for the model) instead of
being fabricated. Each loader documents its mapping.
"""

from __future__ import annotations

import math
from typing import Any, Mapping

FEATURE_ORDER: tuple[str, ...] = (
    "dst_port_class",
    "duration_s",
    "orig_bytes",
    "resp_bytes",
    "orig_pkts",
    "resp_pkts",
    "orig_ip_bytes",
    "resp_ip_bytes",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "down_up_ratio",
    "avg_packet_size",
    "bytes_ratio",
    "syn_flag",
    "ack_flag",
    "fin_flag",
    "rst_flag",
    "psh_flag",
    "urg_flag",
    "conn_state_code",
    "proto_code",
)

PROTO_CODES = {"tcp": 1, "udp": 2, "icmp": 3}

# Destination ports are grouped into service classes. Raw port numbers let a
# tree memorise dataset-specific label artefacts (e.g. "port 21 means attack"
# because one corpus only captured FTP brute force); the class keeps the
# service semantics that transfer across captures.
PORT_CLASS_CODES = {
    1: "web (80/443/8080/8443)",
    2: "file transfer (20/21/139/445)",
    3: "remote access (22/23/3389/5900)",
    4: "mail (25/110/143/465/587/993/995)",
    5: "database (1433/3306/5432/6379/9200/27017)",
    6: "name/time (53/123/5353/67/68)",
    7: "other well-known (<1024)",
    8: "ephemeral / unknown",
}


def port_class_code(value: Any) -> float | None:
    port = _num(value)
    if port is None:
        return None
    port = int(port)
    if port in (53, 123, 5353, 67, 68):
        return 6.0
    if port in (80, 443, 8080, 8000, 8443, 8008):
        return 1.0
    if port in (20, 21, 139, 445, 548):
        return 2.0
    if port in (22, 23, 3389, 5900, 5985):
        return 3.0
    if port in (25, 110, 143, 465, 587, 993, 995):
        return 4.0
    if port in (1433, 3306, 5432, 6379, 9200, 11211, 27017):
        return 5.0
    if port < 1024:
        return 7.0
    return 8.0

# Zeek conn_state values grouped into a small, stable ordinal encoding.
CONN_STATE_CODES = {
    "SF": 1,
    "S0": 2,
    "REJ": 3,
    "RSTO": 4,
    "RSTR": 5,
    "S1": 6,
    "SH": 7,
    "S2": 8,
    "S3": 9,
    "RSTOS0": 10,
    "OTH": 11,
}

# TCP flag columns exposed by CICIDS2017.
_CICIDS_FLAG_MAP = {
    "syn_flag": "SYN Flag Count",
    "ack_flag": "ACK Flag Count",
    "fin_flag": "FIN Flag Count",
    "rst_flag": "RST Flag Count",
    "psh_flag": "PSH Flag Count",
    "urg_flag": "URG Flag Count",
}

# Well-known service -> port mapping used when a dataset carries a service
# name but no port (NSL-KDD).
SERVICE_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ftp-data": 20,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "pop3": 110,
    "imap": 143,
    "netbios-ssn": 139,
    "netbios-ns": 137,
    "snmp": 161,
    "ldap": 389,
    "microsoft-ds": 445,
    "mysql": 3306,
    "postgresql": 5432,
    "rdp": 3389,
    "ntp": 123,
    "dhcp": 67,
    "irc": 194,
}

SAFE_DIVISOR = 1e-6


def _num(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        if value in {"", "-"}:
            return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def _ratio(numerator: Any, denominator: Any) -> float | None:
    num, den = _num(numerator), _num(denominator)
    if num is None or den is None:
        return None
    if den <= 0:
        return 0.0 if num <= 0 else None
    return num / den


def _mean(total: Any, count: Any) -> float | None:
    return _ratio(total, count)


def _code(mapping: Mapping[str, int], value: Any) -> float | None:
    if value is None:
        return None
    key = str(value).strip().lower()
    if key in mapping:
        return float(mapping[key])
    return 0.0


def _proto_code(value: Any) -> float | None:
    if value is None:
        return None
    return float(PROTO_CODES.get(str(value).strip().lower(), 0))


# UNSW-NB15 uses a different state vocabulary than Zeek's conn.log.
UNSW_STATE_MAP = {
    "CON": "SF",
    "FIN": "SF",
    "REQ": "S0",
    "RST": "REJ",
    "INT": "OTH",
    "ECO": "OTH",
    "URN": "OTH",
    "no": "S0",
}


def _conn_state_code(value: Any) -> float | None:
    if value is None:
        return None
    key = str(value).strip()
    if key in UNSW_STATE_MAP:
        return float(CONN_STATE_CODES[UNSW_STATE_MAP[key]])
    return float(CONN_STATE_CODES.get(key.upper(), 0))


def _flags_from_conn_state(state: str | None) -> dict[str, float | None]:
    """Approximate flag presence from a Zeek connection state.

    This is only used for datasets that expose ``conn_state`` but not flags
    (UNSW-NB15). It is deliberately conservative: only flags implied by the
    state machine are set.
    """

    if not state:
        return {"syn_flag": None, "ack_flag": None, "fin_flag": None,
                "rst_flag": None, "psh_flag": None, "urg_flag": None}
    state = state.strip().upper()
    syn = 1.0 if state in {"S0", "S1", "SH", "S2", "S3", "RSTOS0"} else 0.0
    ack = 1.0 if state in {"SF", "SH", "S1", "OTH", "RSTO", "RSTR", "S2", "S3"} else 0.0
    fin = 1.0 if state in {"SF", "SH", "S2", "S3"} else 0.0
    rst = 1.0 if state in {"REJ", "RSTO", "RSTR", "RSTOS0"} else 0.0
    return {
        "syn_flag": syn,
        "ack_flag": ack,
        "fin_flag": fin,
        "rst_flag": rst,
        "psh_flag": 0.0,
        "urg_flag": 0.0,
    }


def _finalize(values: dict[str, Any]) -> dict[str, float | None]:
    """Project an arbitrary feature dict onto ``FEATURE_ORDER``."""

    out = {name: _num(values.get(name)) for name in FEATURE_ORDER}
    out["dst_port_class"] = port_class_code(values.get("dst_port"))
    return out


# --------------------------------------------------------------------------- #
# Zeek conn.log  ->  feature vector
# --------------------------------------------------------------------------- #
def features_from_zeek(event: Any) -> dict[str, float | None] | None:
    """Build a model vector from a :class:`NormalizedEvent`.

    Returns ``None`` for logs that do not carry connection-level volume data
    (dns/http/ssl/...). Those events are still stored and rule-inspected, they
    are simply reported as *unclassified* by the ML stage.
    """

    if getattr(event, "log_type", None) != "conn":
        return None

    duration = _num(event.duration)
    orig_bytes = _num(event.orig_bytes)
    resp_bytes = _num(event.resp_bytes)
    orig_pkts = _num(event.orig_pkts)
    resp_pkts = _num(event.resp_pkts)
    orig_ip_bytes = _num(event.orig_ip_bytes)
    resp_ip_bytes = _num(event.resp_ip_bytes)

    total_bytes = None
    if orig_bytes is not None and resp_bytes is not None:
        total_bytes = orig_bytes + resp_bytes
    total_pkts = None
    if orig_pkts is not None and resp_pkts is not None:
        total_pkts = orig_pkts + resp_pkts

    flow_bytes_per_s = None
    flow_packets_per_s = None
    if duration is not None:
        if duration > 0:
            flow_bytes_per_s = _ratio(total_bytes, duration)
            flow_packets_per_s = _ratio(total_pkts, duration)
        else:
            flow_bytes_per_s = 0.0 if total_bytes == 0 else None
            flow_packets_per_s = 0.0 if total_pkts == 0 else None

    state = event.conn_state
    flags = _flags_from_conn_state(state)

    values = {
        "dst_port": _num(event.dst_port),
        "duration_s": duration,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "orig_ip_bytes": orig_ip_bytes,
        "resp_ip_bytes": resp_ip_bytes,
        "fwd_pkt_len_mean": _mean(orig_bytes, orig_pkts),
        "bwd_pkt_len_mean": _mean(resp_bytes, resp_pkts),
        "flow_bytes_per_s": flow_bytes_per_s,
        "flow_packets_per_s": flow_packets_per_s,
        "down_up_ratio": _ratio(resp_pkts, orig_pkts),
        "avg_packet_size": _mean(total_bytes, total_pkts),
        "bytes_ratio": _ratio(orig_bytes, resp_bytes),
        "conn_state_code": _conn_state_code(state),
        "proto_code": _proto_code(event.proto),
        **flags,
    }
    return _finalize(values)


# --------------------------------------------------------------------------- #
# CICIDS2017  ->  feature vector
# --------------------------------------------------------------------------- #
def features_from_cicids(row: Mapping[str, Any]) -> dict[str, float | None]:
    """Map a CICIDS2017 flow row to the shared schema.

    CICIDS2017 flow features are derived from the same packet stream that
    Zeek summarises in ``conn.log``, so the mapping is direct for duration,
    packet counts, byte counts and TCP flags. The destination port is used to
    infer the transport protocol because the public flow CSV does not carry a
    protocol column; that inference is only used when the dataset lacks it.
    """

    duration_us = _num(row.get("Flow Duration"))
    duration_s = duration_us / 1e6 if duration_us is not None else None

    orig_bytes = _num(row.get("Total Length of Fwd Packets"))
    resp_bytes = _num(row.get("Total Length of Bwd Packets"))
    orig_pkts = _num(row.get("Total Fwd Packets"))
    resp_pkts = _num(row.get("Total Backward Packets"))

    fwd_header = _num(row.get("Fwd Header Length"))
    bwd_header = _num(row.get("Bwd Header Length"))
    orig_ip_bytes = (
        orig_bytes + fwd_header if orig_bytes is not None and fwd_header is not None else orig_bytes
    )
    resp_ip_bytes = (
        resp_bytes + bwd_header if resp_bytes is not None and bwd_header is not None else resp_bytes
    )

    dst_port = _num(row.get("Destination Port"))
    proto = row.get("Protocol")
    if proto is None:
        proto = "udp" if dst_port in (53.0, 123.0, 67.0, 68.0, 5353.0) else "tcp"

    syn = _num(row.get("SYN Flag Count"))
    ack = _num(row.get("ACK Flag Count"))
    fin = _num(row.get("FIN Flag Count"))
    rst = _num(row.get("RST Flag Count"))
    if rst and rst > 0:
        state = "REJ"
    elif syn and syn > 0 and not ack:
        state = "S0"
    elif fin and fin > 0:
        state = "SF"
    elif ack and ack > 0:
        state = "OTH"
    else:
        state = "OTH"

    total_bytes = None
    if orig_bytes is not None and resp_bytes is not None:
        total_bytes = orig_bytes + resp_bytes
    total_pkts = None
    if orig_pkts is not None and resp_pkts is not None:
        total_pkts = orig_pkts + resp_pkts

    values = {
        "dst_port": dst_port,
        "duration_s": duration_s,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "orig_ip_bytes": orig_ip_bytes,
        "resp_ip_bytes": resp_ip_bytes,
        "fwd_pkt_len_mean": _num(row.get("Fwd Packet Length Mean")),
        "bwd_pkt_len_mean": _num(row.get("Bwd Packet Length Mean")),
        "flow_bytes_per_s": _num(row.get("Flow Bytes/s")),
        "flow_packets_per_s": _num(row.get("Flow Packets/s")),
        "down_up_ratio": _num(row.get("Down/Up Ratio")),
        "avg_packet_size": _num(row.get("Average Packet Size")),
        "bytes_ratio": _ratio(orig_bytes, resp_bytes),
        "syn_flag": syn,
        "ack_flag": ack,
        "fin_flag": fin,
        "rst_flag": rst,
        "psh_flag": _num(row.get("PSH Flag Count")),
        "urg_flag": _num(row.get("URG Flag Count")),
        "conn_state_code": _conn_state_code(state),
        "proto_code": _proto_code(proto),
    }
    return _finalize(values)


# --------------------------------------------------------------------------- #
# UNSW-NB15  ->  feature vector
# --------------------------------------------------------------------------- #
def features_from_unsw(row: Mapping[str, Any]) -> dict[str, float | None]:
    """UNSW-NB15 carries Zeek-like flow fields (dur, spkts, sbytes, state)."""

    duration_s = _num(row.get("dur"))
    orig_pkts = _num(row.get("spkts"))
    resp_pkts = _num(row.get("dpkts"))
    orig_bytes = _num(row.get("sbytes"))
    resp_bytes = _num(row.get("dbytes"))

    total_bytes = None
    if orig_bytes is not None and resp_bytes is not None:
        total_bytes = orig_bytes + resp_bytes
    total_pkts = None
    if orig_pkts is not None and resp_pkts is not None:
        total_pkts = orig_pkts + resp_pkts

    state = row.get("state")
    state = UNSW_STATE_MAP.get(str(state).strip(), state) if state is not None else None
    dst_port = _num(row.get("dsport"))
    if dst_port is None:
        service = str(row.get("service", "")).strip().lower()
        if service in SERVICE_PORTS:
            dst_port = float(SERVICE_PORTS[service])

    values = {
        "dst_port": dst_port,
        "duration_s": duration_s,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "orig_ip_bytes": orig_bytes,
        "resp_ip_bytes": resp_bytes,
        "fwd_pkt_len_mean": _mean(orig_bytes, orig_pkts),
        "bwd_pkt_len_mean": _mean(resp_bytes, resp_pkts),
        "flow_bytes_per_s": _ratio(total_bytes, duration_s),
        "flow_packets_per_s": _ratio(total_pkts, duration_s),
        "down_up_ratio": _ratio(resp_pkts, orig_pkts),
        "avg_packet_size": _mean(total_bytes, total_pkts),
        "bytes_ratio": _ratio(orig_bytes, resp_bytes),
        "conn_state_code": _conn_state_code(state),
        "proto_code": _proto_code(row.get("proto")),
        **_flags_from_conn_state(state),
    }
    return _finalize(values)


# --------------------------------------------------------------------------- #
# NSL-KDD  ->  feature vector
# --------------------------------------------------------------------------- #
def features_from_nslkdd(row: Mapping[str, Any]) -> dict[str, float | None]:
    """NSL-KDD has no packet counts; those fields stay ``None`` (NaN).

    ``src_bytes``/``dst_bytes`` map to orig/resp byte volume, ``flag`` maps to
    the Zeek connection state, and ``service`` maps to a well-known port.
    """

    duration_s = _num(row.get("duration"))
    orig_bytes = _num(row.get("src_bytes"))
    resp_bytes = _num(row.get("dst_bytes"))
    service = str(row.get("service", "")).strip().lower()
    dst_port = float(SERVICE_PORTS[service]) if service in SERVICE_PORTS else None
    flag = str(row.get("flag", "")).strip().upper()

    state = {
        "SF": "SF",
        "S0": "S0",
        "REJ": "REJ",
        "RSTO": "RSTO",
        "RSTR": "RSTR",
        "SH": "SH",
        "S1": "S1",
        "S2": "S2",
        "S3": "S3",
        "OTH": "OTH",
        "RSTOS0": "RSTOS0",
    }.get(flag, "OTH")

    values = {
        "dst_port": dst_port,
        "duration_s": duration_s,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_ip_bytes": orig_bytes,
        "resp_ip_bytes": resp_bytes,
        "flow_bytes_per_s": _ratio(
            (orig_bytes or 0) + (resp_bytes or 0) if orig_bytes is not None and resp_bytes is not None else None,
            duration_s,
        ),
        "bytes_ratio": _ratio(orig_bytes, resp_bytes),
        "conn_state_code": _conn_state_code(state),
        "proto_code": _proto_code(row.get("protocol_type")),
        **_flags_from_conn_state(state),
    }
    return _finalize(values)


def vector(features: Mapping[str, Any]) -> list[float]:
    """Convert a feature dict into a model-ready list (NaN for missing)."""

    out: list[float] = []
    for name in FEATURE_ORDER:
        value = _num(features.get(name))
        out.append(math.nan if value is None else float(value))
    return out
