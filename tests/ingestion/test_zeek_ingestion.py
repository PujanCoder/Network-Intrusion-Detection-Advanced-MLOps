from __future__ import annotations

import json
import shutil
from pathlib import Path

from fastapi.testclient import TestClient

from src.ingestion.zeek.parser import parse_zeek_json_line
from src.ingestion.zeek.normalizers.base import normalize_record
from src.ingestion.zeek.service import ZeekIngestionService
from src.serving.app import create_app
from src.serving.config import Settings


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "zeek"


def test_parse_zeek_json_line_valid():
    p = parse_zeek_json_line('{"ts":1,"uid":"U1"}')
    assert p.ok
    assert p.record["uid"] == "U1"


def test_parse_zeek_json_line_malformed():
    p = parse_zeek_json_line("not json")
    assert not p.ok
    assert "json decode error" in (p.error or "")


def test_normalize_conn_record():
    rec = json.loads((FIXTURES / "conn.log").read_text().splitlines()[0])
    env = normalize_record(record=rec, source_file="conn.log", source_offset=0, source_inode="1", sensor_id="s1")
    assert env.log_type == "conn"
    assert env.src_ip == "192.168.1.10"
    assert env.dst_port == 443
    assert env.normalized["conn_state"] == "SF"
    assert env.event_id


def test_service_ingest_once_and_dedup(tmp_path: Path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "conn.log", log_dir / "conn.log")
    shutil.copy(FIXTURES / "dns.log", log_dir / "dns.log")
    db_path = tmp_path / "ids.db"

    svc = ZeekIngestionService(db_path=db_path, log_dir=log_dir, sensor_id="test-sensor")
    counts1 = svc.ingest_once()
    assert counts1["inserted"] == 3
    assert counts1["dead_letter"] == 0

    # Second run should not re-read completed lines (checkpoint at EOF)
    counts2 = svc.ingest_once()
    assert counts2["lines"] == 0
    assert counts2["inserted"] == 0

    status = svc.store.counts()
    assert status["total"] == 3
    assert status["by_log_type"]["conn"] == 2
    assert status["by_log_type"]["dns"] == 1

    # Explicit dedup: ingest same content into fresh dir with fresh checkpoints but same DB
    log_dir2 = tmp_path / "logs2"
    log_dir2.mkdir()
    shutil.copy(FIXTURES / "conn.log", log_dir2 / "conn.log")
    shutil.copy(FIXTURES / "dns.log", log_dir2 / "dns.log")
    svc2 = ZeekIngestionService(db_path=db_path, log_dir=log_dir2, sensor_id="test-sensor")
    counts3 = svc2.ingest_once()
    assert counts3["duplicate"] == 3
    assert counts3["inserted"] == 0
    assert svc2.store.counts()["total"] == 3


def test_service_handles_malformed_lines(tmp_path: Path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "malformed.log", log_dir / "conn.log")
    db_path = tmp_path / "ids.db"
    svc = ZeekIngestionService(db_path=db_path, log_dir=log_dir, sensor_id="test-sensor", log_types=["conn"])
    counts = svc.ingest_once()
    assert counts["dead_letter"] == 1
    assert counts["inserted"] == 2
    assert svc.store.counts()["dead_letters"] == 1


def test_zeek_api_routes(tmp_path: Path, monkeypatch):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    shutil.copy(FIXTURES / "conn.log", log_dir / "conn.log")

    monkeypatch.setenv("IDS_API_KEY", "test-key")
    monkeypatch.setenv("IDS_DB_PATH", str(tmp_path / "ids.db"))
    monkeypatch.setenv("IDS_ZEEK_LOG_DIR", str(log_dir))
    monkeypatch.setenv("IDS_ZEEK_RUN_DIR", str(tmp_path))
    monkeypatch.setenv("IDS_ZEEK_PCAP_DIR", str(tmp_path))
    # create_app reads Settings() at call time; env vars must be set
    app = create_app()
    client = TestClient(app)

    r = client.get("/api/v1/zeek/status", headers={"X-API-Key": "test-key"})
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

    r = client.post(
        "/api/v1/zeek/ingest/dir",
        json={"log_dir": str(log_dir)},
        headers={"X-API-Key": "test-key"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"]["inserted"] == 2

    r = client.get("/api/v1/zeek/events?limit=10", headers={"X-API-Key": "test-key"})
    assert r.status_code == 200
    events = r.json()["events"]
    assert len(events) == 2
    assert events[0]["log_type"] == "conn"
