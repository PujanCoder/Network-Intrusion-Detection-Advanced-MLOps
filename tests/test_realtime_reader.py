"""Incremental tailing: offsets, partial lines, rotation and truncation."""

from __future__ import annotations

import json
import os
from pathlib import Path

from src.realtime.reader import ZeekLogReader
from src.realtime.store import Store

RECORD = {
    "ts": 1_700_000_000.0,
    "uid": "Creader1",
    "id.orig_h": "10.0.0.5",
    "id.orig_p": 51514,
    "id.resp_h": "93.184.216.34",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "duration": 0.5,
    "orig_bytes": 512,
    "resp_bytes": 4821,
    "conn_state": "SF",
    "orig_pkts": 8,
    "resp_pkts": 9,
}


def _uid(event) -> str:
    return event.event_uid.rsplit(":", 1)[-1]


def _line(uid: str = "Creader1", ts: float = 1_700_000_000.0) -> str:
    record = dict(RECORD, uid=uid, ts=ts)
    return json.dumps(record) + "\n"


def test_reads_only_new_lines(tmp_path: Path, store: Store) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = log_dir / "conn.log"
    log.write_text(_line("C1"), encoding="utf-8")

    reader = ZeekLogReader(log_dir, store, "sensor-test")
    first = list(reader.read_new())
    assert [_uid(event) for _, _, event in first] == ["C1"]
    assert list(reader.read_new()) == []

    with log.open("a", encoding="utf-8") as handle:
        handle.write(_line("C2", ts=1_700_000_001.0))
    second = list(reader.read_new())
    assert [_uid(event) for _, _, event in second] == ["C2"]


def test_partial_line_is_buffered_until_complete(tmp_path: Path, store: Store) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = log_dir / "conn.log"
    payload = _line("C3")
    log.write_text(payload[:20], encoding="utf-8")

    reader = ZeekLogReader(log_dir, store, "sensor-test")
    assert list(reader.read_new()) == []

    with log.open("a", encoding="utf-8") as handle:
        handle.write(payload[20:])
    events = list(reader.read_new())
    assert [_uid(event) for _, _, event in events] == ["C3"]


def test_offset_persists_across_reader_instances(tmp_path: Path, store: Store) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = log_dir / "conn.log"
    log.write_text(_line("C4"), encoding="utf-8")

    first_reader = ZeekLogReader(log_dir, store, "sensor-test")
    assert len(list(first_reader.read_new())) == 1

    second_reader = ZeekLogReader(log_dir, store, "sensor-test")
    assert list(second_reader.read_new()) == []


def test_rotation_resets_offset(tmp_path: Path, store: Store) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = log_dir / "conn.log"
    log.write_text(_line("C5"), encoding="utf-8")

    reader = ZeekLogReader(log_dir, store, "sensor-test")
    assert len(list(reader.read_new())) == 1

    os.rename(log, log_dir / "conn.2023-11-14-22-00-00.log.gz")
    log.write_text(_line("C6", ts=1_700_000_002.0), encoding="utf-8")

    events = list(reader.read_new())
    assert [_uid(event) for _, _, event in events] == ["C6"]
    assert reader.stats.rotations >= 1


def test_truncation_resets_offset(tmp_path: Path, store: Store) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = log_dir / "conn.log"
    log.write_text(_line("C7") + _line("C7b", ts=1_700_000_001.0) + _line("C7c", ts=1_700_000_002.0), encoding="utf-8")

    reader = ZeekLogReader(log_dir, store, "sensor-test")
    assert len(list(reader.read_new())) == 3

    log.write_text(_line("C8", ts=1_700_000_003.0), encoding="utf-8")
    events = list(reader.read_new())
    assert [_uid(event) for _, _, event in events] == ["C8"]
    assert reader.stats.truncations >= 1


def test_duplicate_uid_is_not_stored_twice(tmp_path: Path, store: Store) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    log = log_dir / "conn.log"
    log.write_text(_line("C9"), encoding="utf-8")

    reader = ZeekLogReader(log_dir, store, "sensor-test")
    for path, offset, event in reader.read_new():
        row = event.to_row()
        store.insert_event(row, ingested_at=event.ts)

    with log.open("a", encoding="utf-8") as handle:
        handle.write(_line("C9", ts=1_700_000_009.0))

    for path, offset, event in reader.read_new():
        _, inserted = store.insert_event(event.to_row(), ingested_at=event.ts)
        assert inserted is False

    assert store.overview()["total_events"] == 1


def test_sensor_health_reports_directory_state(tmp_path: Path, store: Store) -> None:
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "conn.log").write_text(_line("C10"), encoding="utf-8")

    reader = ZeekLogReader(log_dir, store, "sensor-test")
    list(reader.read_new())
    health = reader.sensor_health()

    assert health["log_dir_exists"] is True
    assert health["log_file_count"] == 1
    assert health["files_tracked"] == 1
