"""Behavioural detector tests: scans, brute force, exfiltration, DNS tunnelling."""

from __future__ import annotations

import pytest

from src.realtime.detectors import DetectorEngine, combine_severity
from src.realtime.features import features_from_zeek
from src.realtime.zeek_parser import NormalizedEvent
from tests.conftest import conn_event


def _rules(engine: DetectorEngine, event: NormalizedEvent) -> set[str]:
    features = features_from_zeek(event) or {}
    return {hit.rule for hit in engine.observe(event, features)}


def test_port_scan_detected() -> None:
    engine = DetectorEngine(alert_cooldown_s=0)
    hits: set[str] = set()
    for index in range(24):
        event = conn_event(
            ts=1_700_000_000.0 + index * 0.5,
            dst_port=1000 + index,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
            orig_pkts=1,
            resp_pkts=0,
        )
        hits |= _rules(engine, event)

    assert "port_scan_sweep" in hits


def test_host_sweep_detected() -> None:
    engine = DetectorEngine(alert_cooldown_s=0)
    hits: set[str] = set()
    for index in range(18):
        event = conn_event(
            ts=1_700_000_000.0 + index * 0.5,
            dst_ip=f"10.0.1.{index + 1}",
            dst_port=445,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
            orig_pkts=1,
            resp_pkts=0,
        )
        hits |= _rules(engine, event)

    assert "host_sweep" in hits


def test_brute_force_detected() -> None:
    engine = DetectorEngine(alert_cooldown_s=0)
    hits: set[str] = set()
    for index in range(12):
        event = conn_event(
            ts=1_700_000_000.0 + index * 2.0,
            dst_port=22,
            conn_state="REJ",
            orig_bytes=40,
            resp_bytes=0,
            orig_pkts=2,
            resp_pkts=0,
        )
        hits |= _rules(engine, event)

    assert "auth_brute_force" in hits


def test_exfiltration_detected() -> None:
    engine = DetectorEngine(alert_cooldown_s=0)
    hits: set[str] = set()
    for index in range(3):
        event = conn_event(
            ts=1_700_000_000.0 + index * 5.0,
            orig_bytes=2_000_000,
            resp_bytes=1_000,
            orig_pkts=1500,
            resp_pkts=10,
        )
        hits |= _rules(engine, event)

    assert "outbound_exfiltration" in hits


def test_dns_tunnelling_detected() -> None:
    engine = DetectorEngine(alert_cooldown_s=0)
    hits: set[str] = set()
    for index in range(22):
        label = f"{'a' * 30}{index:04x}payload"
        event = NormalizedEvent(
            event_uid=f"Cdns{index}",
            ts=1_700_000_000.0 + index,
            log_type="dns",
            sensor="sensor-test",
            source_file="dns.log",
            source_offset=0,
            src_ip="10.0.0.7",
            dst_ip="10.0.0.1",
            dst_port=53,
            proto="udp",
            raw={"query": f"{label}.exfil.example.com", "qtype_name": "A"},
        )
        hits |= _rules(engine, event)

    assert "dns_tunneling" in hits


def test_benign_flow_triggers_nothing() -> None:
    engine = DetectorEngine(alert_cooldown_s=0)
    event = conn_event()
    assert _rules(engine, event) == set()


def test_alert_cooldown_suppresses_repeats() -> None:
    engine = DetectorEngine(alert_cooldown_s=120)
    first: list[str] = []
    second: list[str] = []
    for index in range(24):
        event = conn_event(
            ts=1_700_000_000.0 + index * 0.1,
            dst_port=2000 + index,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
            orig_pkts=1,
            resp_pkts=0,
        )
        first.extend(_rules(engine, event))

    repeated = conn_event(
        ts=1_700_000_010.0,
        dst_port=2023,
        conn_state="S0",
        orig_bytes=0,
        resp_bytes=0,
        orig_pkts=1,
        resp_pkts=0,
    )
    second.extend(_rules(engine, repeated))

    assert "port_scan_sweep" in first
    assert "port_scan_sweep" not in second


@pytest.mark.parametrize(
    ("model", "rules", "expected"),
    [
        ("INFO", [], "INFO"),
        ("INFO", ["MEDIUM"], "MEDIUM"),
        ("HIGH", ["MEDIUM"], "HIGH"),
        ("INFO", ["CRITICAL"], "CRITICAL"),
        (None, ["LOW"], "LOW"),
    ],
)
def test_combine_severity(model: str | None, rules: list[str], expected: str) -> None:
    class Hit:
        def __init__(self, severity: str) -> None:
            self.severity = severity

    assert combine_severity(model, [Hit(severity) for severity in rules]) == expected
