"""Shared fixtures for the real-time NDR test suite."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from src.realtime.config import Settings
from src.realtime.store import Store
from src.realtime.zeek_parser import NormalizedEvent

FIXTURES = Path(__file__).parent / "fixtures" / "zeek"


def _uid(*parts: Any) -> str:
    digest = hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:12]
    return f"C{digest}"


def conn_event(**overrides: Any) -> NormalizedEvent:
    values: dict[str, Any] = {
        "ts": 1_700_000_000.0,
        "src_ip": "10.0.0.5",
        "dst_ip": "93.184.216.34",
        "src_port": 51514,
        "dst_port": 443,
        "proto": "tcp",
        "service": "ssl",
        "conn_state": "SF",
        "duration": 0.45,
        "orig_bytes": 512,
        "resp_bytes": 4821,
        "orig_pkts": 8,
        "resp_pkts": 9,
        "orig_ip_bytes": 912,
        "resp_ip_bytes": 5213,
    }
    values.update(overrides)
    uid = values.pop("uid", None) or _uid(
        values["ts"], values["src_ip"], values["dst_ip"], values["src_port"], values["dst_port"]
    )
    return NormalizedEvent(
        event_uid=uid,
        log_type=values.pop("log_type", "conn"),
        sensor=values.pop("sensor", "sensor-test"),
        source_file=values.pop("source_file", "conn.log"),
        source_offset=values.pop("source_offset", 0),
        raw=values.pop("raw", {}),
        **values,
    )


def event_row(uid: str, **overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "event_uid": uid,
        "ts": 1_700_000_000.0,
        "log_type": "conn",
        "sensor": "sensor-test",
        "source_file": "conn.log",
        "source_offset": 0,
        "src_ip": "10.0.0.5",
        "dst_ip": "93.184.216.34",
        "src_port": 51514,
        "dst_port": 443,
        "proto": "tcp",
        "service": "ssl",
        "conn_state": "SF",
        "duration": 0.45,
        "orig_bytes": 512,
        "resp_bytes": 4821,
        "orig_pkts": 8,
        "resp_pkts": 9,
        "orig_ip_bytes": 912,
        "resp_ip_bytes": 5213,
        "raw_json": '{"uid": "test"}',
    }
    row.update(overrides)
    return row


def prediction(label: str = "BENIGN", **overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "model_name": "zeek-flow-classifier",
        "model_version": "test-version",
        "label": label,
        "is_malicious": label != "BENIGN",
        "confidence": 0.93,
        "malicious_score": 0.07 if label == "BENIGN" else 0.93,
        "threshold": 0.95,
        "severity": "INFO" if label == "BENIGN" else "HIGH",
        "explanation": "test explanation",
        "latency_ms": 2.5,
        "error": None,
    }
    values.update(overrides)
    return values


@pytest.fixture()
def store(tmp_path: Path):
    instance = Store(tmp_path / "ndr.db")
    yield instance
    instance.close()


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    return Settings(
        zeek_log_dir=tmp_path / "zeek",
        db_path=tmp_path / "ndr.db",
        model_path=tmp_path / "missing-model.joblib",
        sensor_id="test-sensor",
        sensor_mode="test",
        poll_interval_s=0.05,
        ingest_enabled=False,
        cors_origins=("http://localhost:5173",),
        retention_days=7,
        frontend_dist=tmp_path / "dist",
        metrics_window_s=300,
        ws_metrics_interval_s=0.2,
        max_events_returned=500,
        max_ws_clients=5,
        ws_queue_size=50,
        api_host="127.0.0.1",
        api_port=8000,
    )
