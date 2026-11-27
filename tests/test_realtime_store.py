"""SQLite persistence, dedupe and query tests."""

from __future__ import annotations

import time

from src.realtime.store import Store
from tests.conftest import event_row, prediction


def test_insert_event_is_idempotent(store: Store) -> None:
    event_id, inserted = store.insert_event(event_row("C1"))
    again_id, inserted_again = store.insert_event(event_row("C1"))

    assert inserted is True
    assert inserted_again is False
    assert event_id == again_id
    assert store.overview()["total_events"] == 1


def test_prediction_and_alert_are_joined_into_event(store: Store) -> None:
    event_id, _ = store.insert_event(event_row("C2", src_ip="10.0.0.99", dst_port=22))
    store.save_prediction(event_id, prediction("BruteForce", severity="HIGH", explanation="ssh guessing"))
    store.save_alert(
        event_id,
        {
            "rule": "auth_brute_force",
            "category": "BruteForce",
            "severity": "HIGH",
            "confidence": 0.8,
            "explanation": "many failed logins",
            "evidence": {"attempts": 40},
        },
    )

    event = store.get_event(event_id)
    assert event is not None
    assert event["prediction"] == "BruteForce"
    assert event["is_malicious"] is True
    assert event["severity"] == "HIGH"
    assert event["alerts"][0]["rule"] == "auth_brute_force"
    assert event["alerts"][0]["evidence"] == {"attempts": 40}


def test_query_filters_by_ip_protocol_prediction_and_severity(store: Store) -> None:
    first, _ = store.insert_event(event_row("C3", src_ip="192.168.1.50", proto="udp", dst_port=53))
    store.save_prediction(first, prediction("DnsTunneling", severity="CRITICAL"))
    second, _ = store.insert_event(event_row("C4", src_ip="10.1.1.1", proto="tcp"))
    store.save_prediction(second, prediction("BENIGN", severity="INFO"))

    assert store.count_events(search="192.168.1.50") == 1
    assert store.count_events(proto="udp") == 1
    assert store.count_events(prediction="DnsTunneling") == 1
    assert store.count_events(severity="CRITICAL") == 1
    assert store.count_events(malicious_only=True) == 1
    assert len(list(store.iter_events(proto="tcp"))) == 1


def test_time_range_filter(store: Store) -> None:
    store.insert_event(event_row("C5", ts=100.0))
    store.insert_event(event_row("C6", ts=200.0))

    rows = store.query_events(start=150.0, end=250.0)
    assert [row["event_uid"] for row in rows] == ["C6"]


def test_overview_counts_and_rates(store: Store) -> None:
    benign, _ = store.insert_event(event_row("C7"))
    store.save_prediction(benign, prediction("BENIGN"))
    attack, _ = store.insert_event(event_row("C8", ts=time.time()))
    store.save_prediction(attack, prediction("DDoS", severity="CRITICAL"))
    unclassified, _ = store.insert_event(event_row("C9", log_type="dns", dst_port=53))
    store.save_prediction(unclassified, prediction(None, is_malicious=False, confidence=None, severity="INFO"))

    overview = store.overview()
    assert overview["total_events"] == 3
    assert overview["attacks"] == 1
    assert overview["benign"] == 1
    assert overview["unclassified"] == 1
    assert overview["critical_alerts"] == 0  # no rule alerts yet
    assert overview["critical_detections"] == 1  # the CRITICAL-severity prediction
    assert overview["avg_prediction_latency_ms"] == 2.5


def test_attack_query_returns_model_and_rule_detections(store: Store) -> None:
    modelled, _ = store.insert_event(event_row("CA", src_ip="203.0.113.9"))
    store.save_prediction(modelled, prediction("PortScan", severity="MEDIUM"))

    ruled, _ = store.insert_event(event_row("CB", src_ip="203.0.113.10"))
    store.save_prediction(ruled, prediction("BENIGN"))
    store.save_alert(
        ruled,
        {
            "rule": "outbound_exfiltration",
            "category": "Exfiltration",
            "severity": "CRITICAL",
            "confidence": 0.9,
            "explanation": "7 MB uploaded",
            "evidence": {"outbound_bytes": 7_000_000},
        },
    )

    attacks = store.query_attacks(limit=10)
    assert {item["event_uid"] for item in attacks} == {"CA", "CB"}
    assert store.count_attacks() == 2


def test_alert_dedupe(store: Store) -> None:
    event_id, _ = store.insert_event(event_row("CC"))
    hit = {
        "rule": "port_scan_sweep",
        "category": "PortScan",
        "severity": "HIGH",
        "confidence": 0.8,
        "explanation": "scan",
        "evidence": {},
    }
    assert store.save_alert(event_id, hit) is True
    assert store.save_alert(event_id, hit) is False
    assert store.overview()["total_alerts"] == 1


def test_ingestion_state_roundtrip(store: Store) -> None:
    store.set_ingestion_state("/tmp/conn.log", inode=42, offset=1024, size=2048)
    state = store.get_ingestion_state()

    assert state["/tmp/conn.log"]["offset"] == 1024
    assert state["/tmp/conn.log"]["inode"] == 42


def test_processing_delay(store: Store) -> None:
    store.insert_event(event_row("CD", ts=1000.0), ingested_at=1000.25)
    delay = store.processing_delay()
    assert delay["samples"] == 1
    assert delay["avg_delay_s"] == 0.25


def test_dead_letters_are_recorded(store: Store) -> None:
    store.record_dead_letter("conn.log", 10, "not json", "parse error")
    assert store.dead_letter_count() == 1


def test_db_status_reports_integrity(store: Store) -> None:
    status = store.db_status()
    assert status["integrity"] == "ok"
    assert status["events"] == 0
    assert status["journal_mode"].lower() in {"wal", "delete", "memory", "truncate", "persist", "off"}

def test_transaction_hides_partial_writes_from_readers(store: Store, tmp_path) -> None:
    """A flow must be invisible until its prediction is written too."""

    observer = Store(store.db_path)

    with store.transaction():
        event_id, inserted = store.insert_event(event_row("TX1"))
        assert inserted is True
        assert observer.count_events() == 0
        store.save_prediction(event_id, prediction("DoS", severity="CRITICAL"))
        assert observer.count_events() == 0

    assert observer.count_events() == 1
    assert observer.overview()["unclassified"] == 0
    observer.close()
