from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any


ZEEK_SCHEMA = """
CREATE TABLE IF NOT EXISTS zeek_events (
    event_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    log_type TEXT NOT NULL,
    ts TEXT NOT NULL,
    ingested_at TEXT NOT NULL,
    sensor_id TEXT NOT NULL,
    uid TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    proto TEXT,
    service TEXT,
    severity TEXT,
    raw_json TEXT NOT NULL,
    normalized_json TEXT NOT NULL,
    parse_status TEXT NOT NULL,
    parse_errors_json TEXT,
    source_file TEXT NOT NULL,
    source_offset INTEGER NOT NULL,
    source_inode TEXT
);
CREATE INDEX IF NOT EXISTS idx_zeek_ts ON zeek_events(ts);
CREATE INDEX IF NOT EXISTS idx_zeek_ingested ON zeek_events(ingested_at);
CREATE INDEX IF NOT EXISTS idx_zeek_log_type ON zeek_events(log_type, ts);
CREATE INDEX IF NOT EXISTS idx_zeek_uid ON zeek_events(uid);
CREATE INDEX IF NOT EXISTS idx_zeek_src ON zeek_events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_zeek_dst ON zeek_events(dst_ip, ts);

CREATE TABLE IF NOT EXISTS zeek_dead_letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    source_offset INTEGER NOT NULL,
    source_inode TEXT,
    error TEXT NOT NULL,
    raw_line TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_zeek_dl_created ON zeek_dead_letters(created_at);

CREATE TABLE IF NOT EXISTS zeek_ingestion_status (
    sensor_id TEXT PRIMARY KEY,
    last_seen_ts TEXT,
    last_ingested_at TEXT,
    last_error TEXT,
    events_ingested INTEGER NOT NULL DEFAULT 0,
    events_duplicate INTEGER NOT NULL DEFAULT 0,
    dead_letters INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zeek_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    log_type TEXT NOT NULL,
    sensor_id TEXT NOT NULL,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, proto TEXT, service TEXT,
    label TEXT NOT NULL,
    is_attack INTEGER NOT NULL,
    confidence REAL,
    probabilities_json TEXT,
    status TEXT NOT NULL,
    reason TEXT,
    model_schema_version TEXT,
    raw_event_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_zeek_det_ts ON zeek_detections(ts);
CREATE INDEX IF NOT EXISTS idx_zeek_det_attack ON zeek_detections(is_attack, ts);
CREATE INDEX IF NOT EXISTS idx_zeek_det_event ON zeek_detections(event_id);
"""


class ZeekStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(ZEEK_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def insert_event(self, event: dict[str, Any]) -> bool:
        """Insert event idempotently. Returns True if inserted, False if duplicate."""
        with self._lock, self._conn() as c:
            cur = c.execute(
                """
                INSERT OR IGNORE INTO zeek_events (
                    event_id, source, log_type, ts, ingested_at, sensor_id, uid,
                    src_ip, src_port, dst_ip, dst_port, proto, service, severity,
                    raw_json, normalized_json, parse_status, parse_errors_json,
                    source_file, source_offset, source_inode
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["event_id"], event.get("source", "zeek"), event["log_type"], event["ts"],
                    event["ingested_at"], event["sensor_id"], event.get("uid"),
                    event.get("src_ip"), event.get("src_port"), event.get("dst_ip"), event.get("dst_port"),
                    event.get("proto"), event.get("service"), event.get("severity"),
                    json.dumps(event.get("raw", {}), default=str),
                    json.dumps(event.get("normalized", {}), default=str),
                    event.get("parse_status", "ok"),
                    json.dumps(event.get("parse_errors", []), default=str),
                    event["source_file"], event["source_offset"], event.get("source_inode"),
                ),
            )
            inserted = cur.rowcount > 0
            self._update_status(c, event["sensor_id"], event.get("ts"), event["ingested_at"], inserted=inserted)
            return inserted

    def insert_dead_letter(self, *, sensor_id: str, source_file: str, source_offset: int, source_inode: str | None, error: str, raw_line: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            c.execute(
                """
                INSERT INTO zeek_dead_letters (sensor_id, source_file, source_offset, source_inode, error, raw_line, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (sensor_id, source_file, source_offset, source_inode, error, raw_line[:10000], now),
            )
            c.execute(
                """
                INSERT INTO zeek_ingestion_status (sensor_id, dead_letters, updated_at)
                VALUES (?, 1, ?)
                ON CONFLICT(sensor_id) DO UPDATE SET
                    dead_letters = dead_letters + 1,
                    last_error = excluded.last_error,
                    updated_at = excluded.updated_at
                """,
                (sensor_id, now),
            )
            c.execute("UPDATE zeek_ingestion_status SET last_error=? WHERE sensor_id=?", (error, sensor_id))

    def _update_status(self, conn: sqlite3.Connection, sensor_id: str, last_seen_ts: str | None, ingested_at: str, *, inserted: bool) -> None:
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO zeek_ingestion_status (sensor_id, last_seen_ts, last_ingested_at, events_ingested, events_duplicate, dead_letters, updated_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(sensor_id) DO UPDATE SET
                last_seen_ts=COALESCE(excluded.last_seen_ts, last_seen_ts),
                last_ingested_at=excluded.last_ingested_at,
                events_ingested=events_ingested + excluded.events_ingested,
                events_duplicate=events_duplicate + excluded.events_duplicate,
                updated_at=excluded.updated_at
            """,
            (sensor_id, last_seen_ts, ingested_at, 1 if inserted else 0, 0 if inserted else 1, now),
        )

    def recent_events(self, limit: int = 100, log_type: str | None = None) -> list[dict[str, Any]]:
        q = "SELECT * FROM zeek_events"
        params: list[Any] = []
        if log_type:
            q += " WHERE log_type=?"
            params.append(log_type)
        q += " ORDER BY id_rowid DESC LIMIT ?"
        # id_rowid not present; use rowid
        q = q.replace("id_rowid", "rowid")
        params.append(limit)
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(q, tuple(params)).fetchall()]
        for r in rows:
            r["raw"] = json.loads(r.pop("raw_json", "{}"))
            r["normalized"] = json.loads(r.pop("normalized_json", "{}"))
            r["parse_errors"] = json.loads(r.pop("parse_errors_json", "[]"))
        return rows

    def status(self, sensor_id: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        with self._conn() as c:
            if sensor_id:
                row = c.execute("SELECT * FROM zeek_ingestion_status WHERE sensor_id=?", (sensor_id,)).fetchone()
                return dict(row) if row else {}
            rows = [dict(r) for r in c.execute("SELECT * FROM zeek_ingestion_status ORDER BY updated_at DESC").fetchall()]
            return rows

    def insert_detection(self, event: dict[str, Any], prediction: dict[str, Any]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock, self._conn() as c:
            cur = c.execute(
                """
                INSERT INTO zeek_detections (
                    event_id, ts, log_type, sensor_id, src_ip, src_port, dst_ip, dst_port, proto, service,
                    label, is_attack, confidence, probabilities_json, status, reason, model_schema_version, raw_event_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.get("event_id"), event.get("ts"), event.get("log_type"), event.get("sensor_id"),
                    event.get("src_ip"), event.get("src_port"), event.get("dst_ip"), event.get("dst_port"),
                    event.get("proto"), event.get("service"),
                    prediction.get("label", "UNCLASSIFIED"), int(bool(prediction.get("is_attack", False))),
                    prediction.get("confidence"),
                    json.dumps(prediction.get("probabilities"), default=str) if prediction.get("probabilities") is not None else None,
                    prediction.get("status", "unknown"), prediction.get("reason"),
                    prediction.get("schema_version"),
                    json.dumps(event, default=str),
                    now,
                ),
            )
            return int(cur.lastrowid or 0)

    def recent_detections(self, limit: int = 100, only_attacks: bool = False) -> list[dict[str, Any]]:
        q = "SELECT * FROM zeek_detections"
        params: list[Any] = []
        if only_attacks:
            q += " WHERE is_attack = 1"
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._conn() as c:
            rows = [dict(r) for r in c.execute(q, tuple(params)).fetchall()]
        for r in rows:
            r["probabilities"] = json.loads(r.pop("probabilities_json") or "null")
            r["raw_event"] = json.loads(r.pop("raw_event_json") or "{}")
        return rows

    def counts(self) -> dict[str, int]:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) c FROM zeek_events").fetchone()["c"]
            by_type_rows = c.execute("SELECT log_type, COUNT(*) c FROM zeek_events GROUP BY log_type").fetchall()
            dead = c.execute("SELECT COUNT(*) c FROM zeek_dead_letters").fetchone()["c"]
            det_total = c.execute("SELECT COUNT(*) c FROM zeek_detections").fetchone()["c"]
            det_attacks = c.execute("SELECT COUNT(*) c FROM zeek_detections WHERE is_attack=1").fetchone()["c"]
            det_scored = c.execute("SELECT COUNT(*) c FROM zeek_detections WHERE status='scored'").fetchone()["c"]
        return {
            "total": total,
            "dead_letters": dead,
            "by_log_type": {r["log_type"]: r["c"] for r in by_type_rows},
            "detections_total": det_total,
            "detections_attacks": det_attacks,
            "detections_scored": det_scored,
        }

    def apply_retention(self, retention_days: int) -> int:
        if retention_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._lock, self._conn() as c:
            cur = c.execute("DELETE FROM zeek_events WHERE ingested_at < ?", (cutoff,))
            cur2 = c.execute("DELETE FROM zeek_dead_letters WHERE created_at < ?", (cutoff,))
            return (cur.rowcount or 0) + (cur2.rowcount or 0)
