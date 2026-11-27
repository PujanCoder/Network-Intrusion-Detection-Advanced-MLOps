"""SQLite persistence for the real-time NDR platform.

Design notes
------------
* One connection guarded by a lock: the write volume of a single Zeek sensor
  is far below what SQLite serialisation costs, and it keeps reads
  consistent with writes without a connection pool.
* WAL mode so API readers never block the ingestion thread.
* ``events.event_uid`` is UNIQUE, which is the second line of defence against
  duplicate processing (the first is the persisted file offset).
* Predictions, alerts and ingestion offsets live in separate tables so model
  monitoring and sensor monitoring are plain SQL aggregates.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator

BURST_WINDOW_S = 10  # seconds used for the instantaneous arrival rate

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_uid TEXT NOT NULL UNIQUE,
    ts REAL NOT NULL,
    ingested_at REAL NOT NULL,
    sensor TEXT NOT NULL,
    log_type TEXT NOT NULL,
    source_file TEXT,
    source_offset INTEGER,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    proto TEXT,
    service TEXT,
    conn_state TEXT,
    duration REAL,
    orig_bytes INTEGER,
    resp_bytes INTEGER,
    orig_pkts INTEGER,
    resp_pkts INTEGER,
    orig_ip_bytes INTEGER,
    resp_ip_bytes INTEGER,
    raw_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_ingested ON events(ingested_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_dst ON events(dst_ip);

CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL UNIQUE REFERENCES events(id) ON DELETE CASCADE,
    model_name TEXT,
    model_version TEXT,
    label TEXT,
    is_malicious INTEGER,
    confidence REAL,
    malicious_score REAL,
    threshold REAL,
    severity TEXT,
    explanation TEXT,
    latency_ms REAL,
    error TEXT,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_predictions_created ON predictions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_predictions_label ON predictions(label);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
    rule TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL,
    explanation TEXT,
    evidence_json TEXT,
    dedupe_key TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS ingestion_state (
    source_file TEXT PRIMARY KEY,
    inode INTEGER,
    offset INTEGER NOT NULL,
    size INTEGER,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS dead_letters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_file TEXT,
    line_offset INTEGER,
    payload TEXT,
    error TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS service_state (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at REAL NOT NULL
);
"""

EVENT_COLUMNS = (
    "event_uid, ts, log_type, sensor, source_file, source_offset, src_ip, dst_ip, "
    "src_port, dst_port, proto, service, conn_state, duration, orig_bytes, resp_bytes, "
    "orig_pkts, resp_pkts, orig_ip_bytes, resp_ip_bytes, raw_json"
)

EVENT_SELECT = f"""
SELECT e.id, e.event_uid, e.ts, e.ingested_at, e.log_type, e.sensor, e.src_ip, e.dst_ip,
       e.src_port, e.dst_port, e.proto, e.service, e.conn_state, e.duration,
       e.orig_bytes, e.resp_bytes, e.orig_pkts, e.resp_pkts,
       e.orig_ip_bytes, e.resp_ip_bytes, e.raw_json,
       p.label AS prediction, p.confidence AS confidence, p.severity AS severity,
       p.is_malicious AS is_malicious, p.explanation AS explanation,
       p.latency_ms AS latency_ms, p.model_name AS model_name,
       p.model_version AS model_version, p.error AS prediction_error,
       p.threshold AS threshold
FROM events e
LEFT JOIN predictions p ON p.event_id = e.id
"""


class Store:
    """Thread-safe SQLite repository."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tx_depth = 0
        self._conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, timeout=30.0
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # plumbing
    # ------------------------------------------------------------------ #
    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cursor = self._conn.cursor()
            try:
                yield cursor
                if self._tx_depth == 0:
                    self._conn.commit()
            except Exception:
                if self._tx_depth == 0:
                    self._conn.rollback()
                raise
            finally:
                cursor.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Group several writes so readers never see an event without its prediction."""

        with self._lock:
            self._tx_depth += 1
            try:
                yield
                if self._tx_depth == 1:
                    self._conn.commit()
            except Exception:
                if self._tx_depth == 1:
                    self._conn.rollback()
                raise
            finally:
                self._tx_depth -= 1

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ #
    # writes
    # ------------------------------------------------------------------ #
    def insert_event(self, row: dict[str, Any], ingested_at: float | None = None) -> tuple[int, bool]:
        values = (
            row["event_uid"], float(row["ts"]),
            row["log_type"], row["sensor"], row.get("source_file"), row.get("source_offset"),
            row.get("src_ip"), row.get("dst_ip"), row.get("src_port"), row.get("dst_port"),
            row.get("proto"), row.get("service"), row.get("conn_state"),
            row.get("duration"), row.get("orig_bytes"), row.get("resp_bytes"),
            row.get("orig_pkts"), row.get("resp_pkts"),
            row.get("orig_ip_bytes"), row.get("resp_ip_bytes"), row.get("raw_json", "{}"),
            ingested_at or time.time(),
        )
        placeholders = ", ".join("?" for _ in values)
        with self._cursor() as cur:
            cur.execute(
                f"INSERT OR IGNORE INTO events ({EVENT_COLUMNS}, ingested_at) VALUES ({placeholders})",
                values,
            )
            inserted = cur.rowcount == 1
            if not inserted:
                cur.execute("SELECT id FROM events WHERE event_uid = ?", (row["event_uid"],))
                existing = cur.fetchone()
                return (int(existing["id"]) if existing else -1), False
            return int(cur.lastrowid), True

    def save_prediction(self, event_id: int, prediction: dict[str, Any]) -> None:
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO predictions (
                    event_id, model_name, model_version, label, is_malicious,
                    confidence, malicious_score, threshold, severity, explanation,
                    latency_ms, error, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    label=excluded.label,
                    is_malicious=excluded.is_malicious,
                    confidence=excluded.confidence,
                    malicious_score=excluded.malicious_score,
                    severity=excluded.severity,
                    explanation=excluded.explanation,
                    latency_ms=excluded.latency_ms,
                    error=excluded.error,
                    created_at=excluded.created_at
                """,
                (
                    event_id,
                    prediction.get("model_name"),
                    prediction.get("model_version"),
                    prediction.get("label"),
                    1 if prediction.get("is_malicious") else 0,
                    prediction.get("confidence"),
                    prediction.get("malicious_score"),
                    prediction.get("threshold"),
                    prediction.get("severity"),
                    prediction.get("explanation"),
                    prediction.get("latency_ms"),
                    prediction.get("error"),
                    prediction.get("created_at") or time.time(),
                ),
            )

    def save_alert(self, event_id: int, hit: dict[str, Any], created_at: float | None = None) -> bool:
        dedupe_key = "|".join(
            str(part)
            for part in (
                hit.get("rule"),
                event_id,
                hit.get("evidence", {}).get("occurrences", 1),
            )
        )
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT OR IGNORE INTO alerts (
                    event_id, rule, category, severity, confidence,
                    explanation, evidence_json, dedupe_key, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    hit.get("rule"),
                    hit.get("category"),
                    hit.get("severity"),
                    hit.get("confidence"),
                    hit.get("explanation"),
                    json.dumps(hit.get("evidence", {}), default=str),
                    dedupe_key,
                    created_at or time.time(),
                ),
            )
            return cur.rowcount == 1

    def record_dead_letter(self, source_file: str, offset: int, payload: str, error: str) -> None:
        with self._cursor() as cur:
            cur.execute(
                "INSERT INTO dead_letters (source_file, line_offset, payload, error, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (source_file, offset, payload[:4000], error[:2000], time.time()),
            )

    def set_ingestion_state(self, source_file: str, inode: int | None, offset: int, size: int | None) -> None:
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO ingestion_state (source_file, inode, offset, size, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_file) DO UPDATE SET
                    inode=excluded.inode, offset=excluded.offset,
                    size=excluded.size, updated_at=excluded.updated_at
                """,
                (source_file, inode, offset, size, time.time()),
            )

    def set_service_state(self, key: str, value: Any) -> None:
        with self._cursor() as cur:
            cur.execute(
                """
                INSERT INTO service_state (key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                (key, json.dumps(value, default=str), time.time()),
            )

    def purge_older_than(self, days: int) -> int:
        if days <= 0:
            return 0
        cutoff = time.time() - days * 86400
        with self._cursor() as cur:
            cur.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            return cur.rowcount

    # ------------------------------------------------------------------ #
    # reads
    # ------------------------------------------------------------------ #
    def get_ingestion_state(self) -> dict[str, dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM ingestion_state")
            return {row["source_file"]: dict(row) for row in cur.fetchall()}

    def get_service_state(self, key: str, default: Any = None) -> Any:
        with self._cursor() as cur:
            cur.execute("SELECT value FROM service_state WHERE key = ?", (key,))
            row = cur.fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except (TypeError, json.JSONDecodeError):
            return default

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        with self._cursor() as cur:
            cur.execute(EVENT_SELECT + " WHERE e.id = ?", (event_id,))
            row = cur.fetchone()
            if not row:
                return None
            event = self._event_row(row)
            cur.execute(
                "SELECT rule, category, severity, confidence, explanation, evidence_json, created_at "
                "FROM alerts WHERE event_id = ? ORDER BY id",
                (event_id,),
            )
            event["alerts"] = [self._alert_row(alert) for alert in cur.fetchall()]
            return event

    def query_events(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        search: str | None = None,
        proto: str | None = None,
        prediction: str | None = None,
        severity: str | None = None,
        start: float | None = None,
        end: float | None = None,
        malicious_only: bool = False,
        order: str = "desc",
    ) -> list[dict[str, Any]]:
        where, params = self._event_filters(
            search=search, proto=proto, prediction=prediction,
            severity=severity, start=start, end=end, malicious_only=malicious_only,
        )
        direction = "DESC" if order.lower() != "asc" else "ASC"
        sql = f"{EVENT_SELECT} {where} ORDER BY e.ts {direction}, e.id {direction} LIMIT ? OFFSET ?"
        with self._cursor() as cur:
            cur.execute(sql, (*params, limit, offset))
            return [self._event_row(row) for row in cur.fetchall()]

    def count_events(
        self,
        *,
        search: str | None = None,
        proto: str | None = None,
        prediction: str | None = None,
        severity: str | None = None,
        start: float | None = None,
        end: float | None = None,
        malicious_only: bool = False,
    ) -> int:
        where, params = self._event_filters(
            search=search, proto=proto, prediction=prediction,
            severity=severity, start=start, end=end, malicious_only=malicious_only,
        )
        sql = (
            "SELECT COUNT(*) AS n FROM events e "
            "LEFT JOIN predictions p ON p.event_id = e.id " + where
        )
        with self._cursor() as cur:
            cur.execute(sql, params)
            return int(cur.fetchone()["n"])

    def iter_events(self, **filters: Any) -> Iterable[dict[str, Any]]:
        """Stream filtered events for CSV export (no artificial row cap)."""

        where, params = self._event_filters(**filters)
        sql = f"{EVENT_SELECT} {where} ORDER BY e.ts DESC"
        with self._lock:
            cursor = self._conn.cursor()
            try:
                cursor.execute(sql, params)
                for row in cursor:
                    yield self._event_row(row)
            finally:
                cursor.close()

    @staticmethod
    def _event_filters(
        *,
        search: str | None = None,
        proto: str | None = None,
        prediction: str | None = None,
        severity: str | None = None,
        start: float | None = None,
        end: float | None = None,
        malicious_only: bool = False,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if search:
            like = f"%{search.strip()}%"
            clauses.append(
                "(e.src_ip LIKE ? OR e.dst_ip LIKE ? OR e.event_uid LIKE ? "
                "OR e.service LIKE ? OR e.raw_json LIKE ?)"
            )
            params.extend([like] * 5)
        if proto:
            clauses.append("LOWER(e.proto) = ?")
            params.append(proto.lower())
        if prediction:
            if prediction.upper() == "UNCLASSIFIED":
                clauses.append("p.label IS NULL")
            else:
                clauses.append("UPPER(p.label) = ?")
                params.append(prediction.upper())
        if severity:
            clauses.append("UPPER(p.severity) = ?")
            params.append(severity.upper())
        if start is not None:
            clauses.append("e.ts >= ?")
            params.append(float(start))
        if end is not None:
            clauses.append("e.ts <= ?")
            params.append(float(end))
        if malicious_only:
            clauses.append("p.is_malicious = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    @staticmethod
    def _event_row(row: sqlite3.Row) -> dict[str, Any]:
        raw_json = row["raw_json"]
        try:
            raw = json.loads(raw_json) if raw_json else {}
        except json.JSONDecodeError:
            raw = {}
        return {
            "id": row["id"],
            "event_uid": row["event_uid"],
            "ts": row["ts"],
            "ingested_at": row["ingested_at"],
            "log_type": row["log_type"],
            "sensor": row["sensor"],
            "src_ip": row["src_ip"],
            "dst_ip": row["dst_ip"],
            "src_port": row["src_port"],
            "dst_port": row["dst_port"],
            "proto": row["proto"],
            "service": row["service"],
            "conn_state": row["conn_state"],
            "duration": row["duration"],
            "orig_bytes": row["orig_bytes"],
            "resp_bytes": row["resp_bytes"],
            "orig_pkts": row["orig_pkts"],
            "resp_pkts": row["resp_pkts"],
            "orig_ip_bytes": row["orig_ip_bytes"],
            "resp_ip_bytes": row["resp_ip_bytes"],
            "prediction": row["prediction"],
            "confidence": row["confidence"],
            "severity": row["severity"],
            "is_malicious": bool(row["is_malicious"]) if row["is_malicious"] is not None else None,
            "explanation": row["explanation"],
            "latency_ms": row["latency_ms"],
            "model_name": row["model_name"],
            "model_version": row["model_version"],
            "prediction_error": row["prediction_error"],
            "threshold": row["threshold"],
            "raw": raw,
        }

    @staticmethod
    def _alert_row(row: sqlite3.Row) -> dict[str, Any]:
        try:
            evidence = json.loads(row["evidence_json"] or "{}")
        except json.JSONDecodeError:
            evidence = {}
        return {
            "rule": row["rule"],
            "category": row["category"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "explanation": row["explanation"],
            "evidence": evidence,
            "created_at": row["created_at"],
        }

    # ------------------------------------------------------------------ #
    # aggregates
    # ------------------------------------------------------------------ #
    def overview(self, window_s: int = 300) -> dict[str, Any]:
        now = time.time()
        since = now - window_s
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n, MAX(ts) AS last_ts, MAX(ingested_at) AS last_ingest FROM events")
            totals = cur.fetchone()
            cur.execute("SELECT COUNT(*) AS n FROM events WHERE ingested_at >= ?", (since,))
            recent_events = int(cur.fetchone()["n"])

            cur.execute("SELECT COUNT(*) AS n FROM predictions WHERE created_at >= ?", (since,))
            recent_predictions = int(cur.fetchone()["n"])

            # Arrival rate over a short window so an idle sensor reads 0/s instead of
            # coasting on the 5-minute average.
            burst_since = now - BURST_WINDOW_S
            cur.execute("SELECT COUNT(*) AS n FROM events WHERE ingested_at >= ?", (burst_since,))
            burst_events = int(cur.fetchone()["n"])
            cur.execute(
                "SELECT COUNT(*) AS n FROM predictions WHERE created_at >= ?", (burst_since,)
            )
            burst_predictions = int(cur.fetchone()["n"])

            cur.execute("SELECT COUNT(*) AS n FROM predictions")
            total_predictions = int(cur.fetchone()["n"])

            cur.execute("SELECT COUNT(*) AS n FROM predictions WHERE is_malicious = 1")
            attacks = int(cur.fetchone()["n"])

            cur.execute(
                "SELECT COUNT(*) AS n FROM predictions "
                "WHERE is_malicious = 0 AND label IS NOT NULL AND label != 'UNCLASSIFIED'"
            )
            benign = int(cur.fetchone()["n"])

            cur.execute(
                "SELECT COUNT(*) AS n FROM events e LEFT JOIN predictions p ON p.event_id = e.id "
                "WHERE p.label IS NULL OR p.error IS NOT NULL"
            )
            unclassified = int(cur.fetchone()["n"])

            cur.execute(
                "SELECT COUNT(*) AS n FROM events e JOIN predictions p ON p.event_id = e.id "
                "WHERE p.is_malicious = 0 AND EXISTS ("
                "  SELECT 1 FROM alerts a WHERE a.event_id = e.id AND a.severity IN ('HIGH','CRITICAL'))"
            )
            suspicious = int(cur.fetchone()["n"])

            cur.execute("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'CRITICAL'")
            critical_alerts = int(cur.fetchone()["n"])

            cur.execute(
                "SELECT COUNT(*) AS n FROM events e WHERE "
                "EXISTS (SELECT 1 FROM predictions p WHERE p.event_id = e.id AND p.severity = 'CRITICAL') "
                "OR EXISTS (SELECT 1 FROM alerts a WHERE a.event_id = e.id AND a.severity = 'CRITICAL')"
            )
            critical_detections = int(cur.fetchone()["n"])

            cur.execute("SELECT COUNT(*) AS n FROM alerts")
            total_alerts = int(cur.fetchone()["n"])

            cur.execute("SELECT COUNT(*) AS n FROM dead_letters")
            dead_letters = int(cur.fetchone()["n"])

            cur.execute("SELECT COUNT(*) AS n FROM predictions WHERE error IS NOT NULL")
            model_errors = int(cur.fetchone()["n"])

            cur.execute(
                "SELECT AVG(latency_ms) AS avg_latency, COUNT(*) AS n FROM predictions "
                "WHERE created_at >= ? AND latency_ms IS NOT NULL",
                (since,),
            )
            latency_row = cur.fetchone()

        return {
            "total_events": int(totals["n"]),
            "total_predictions": total_predictions,
            "attacks": attacks,
            "benign": benign,
            "suspicious": suspicious,
            "unclassified": unclassified,
            "critical_alerts": critical_alerts,
            "critical_detections": critical_detections,
            "total_alerts": total_alerts,
            "dead_letters": dead_letters,
            "model_errors": model_errors,
            "events_per_second": round(recent_events / window_s, 3),
            "predictions_per_second": round(recent_predictions / window_s, 3),
            "events_per_second_live": round(burst_events / BURST_WINDOW_S, 3),
            "predictions_per_second_live": round(burst_predictions / BURST_WINDOW_S, 3),
            "burst_window_s": BURST_WINDOW_S,
            "avg_prediction_latency_ms": round(latency_row["avg_latency"], 2) if latency_row["avg_latency"] is not None else None,
            "last_event_ts": totals["last_ts"],
            "last_ingest_ts": totals["last_ingest"],
            "seconds_since_last_event": round(now - totals["last_ingest"], 1) if totals["last_ingest"] else None,
            "window_s": window_s,
            "generated_at": now,
        }

    def time_series(self, seconds: int = 120) -> list[dict[str, Any]]:
        now = int(time.time())
        start = now - seconds
        with self._cursor() as cur:
            cur.execute(
                "SELECT CAST(ts AS INTEGER) AS bucket, COUNT(*) AS events, "
                "COALESCE(SUM(orig_bytes), 0) + COALESCE(SUM(resp_bytes), 0) AS bytes "
                "FROM events WHERE ts >= ? GROUP BY bucket",
                (start,),
            )
            events = {int(row["bucket"]): row for row in cur.fetchall()}

            cur.execute(
                "SELECT CAST(created_at AS INTEGER) AS bucket, COUNT(*) AS predictions "
                "FROM predictions WHERE created_at >= ? GROUP BY bucket",
                (start,),
            )
            predictions = {int(row["bucket"]): int(row["predictions"]) for row in cur.fetchall()}

        series = []
        for bucket in range(start, now + 1):
            row = events.get(bucket)
            series.append(
                {
                    "t": bucket,
                    "events": int(row["events"]) if row else 0,
                    "predictions": predictions.get(bucket, 0),
                    "bytes": int(row["bytes"]) if row else 0,
                }
            )
        return series

    def attack_distribution(self, seconds: int = 86400) -> list[dict[str, Any]]:
        since = time.time() - seconds
        with self._cursor() as cur:
            cur.execute(
                "SELECT label, COUNT(*) AS n FROM predictions "
                "WHERE is_malicious = 1 AND created_at >= ? GROUP BY label ORDER BY n DESC",
                (since,),
            )
            return [{"label": row["label"] or "UNKNOWN", "count": int(row["n"])} for row in cur.fetchall()]

    def protocol_distribution(self, seconds: int = 86400) -> list[dict[str, Any]]:
        since = time.time() - seconds
        with self._cursor() as cur:
            cur.execute(
                "SELECT COALESCE(NULLIF(proto, ''), 'unknown') AS proto, COUNT(*) AS n "
                "FROM events WHERE ts >= ? GROUP BY proto ORDER BY n DESC LIMIT 12",
                (since,),
            )
            return [{"label": row["proto"], "count": int(row["n"])} for row in cur.fetchall()]

    def severity_distribution(self, seconds: int = 86400) -> list[dict[str, Any]]:
        """Per-event severity, taking the highest of the model and rule verdicts."""

        since = time.time() - seconds
        rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        with self._cursor() as cur:
            cur.execute(
                "SELECT event_id, UPPER(severity) AS severity FROM predictions "
                "WHERE created_at >= ? AND severity IS NOT NULL "
                "UNION ALL "
                "SELECT event_id, UPPER(severity) AS severity FROM alerts WHERE created_at >= ?",
                (since, since),
            )
            best: dict[int, str] = {}
            for row in cur.fetchall():
                severity = row["severity"] or "INFO"
                if rank.get(severity, 0) > rank.get(best.get(row["event_id"], "INFO"), 0):
                    best[row["event_id"]] = severity
        counts: dict[str, int] = {}
        for severity in best.values():
            counts[severity] = counts.get(severity, 0) + 1
        return [
            {"label": severity, "count": counts[severity]}
            for severity in sorted(counts, key=lambda item: rank.get(item, 0), reverse=True)
        ]

    def top_ips(self, field: str = "src_ip", limit: int = 10, seconds: int = 86400) -> list[dict[str, Any]]:
        if field not in {"src_ip", "dst_ip"}:
            raise ValueError("field must be src_ip or dst_ip")
        since = time.time() - seconds
        with self._cursor() as cur:
            cur.execute(
                f"SELECT {field} AS ip, COUNT(*) AS n FROM events "
                f"WHERE ts >= ? AND {field} IS NOT NULL GROUP BY ip ORDER BY n DESC LIMIT ?",
                (since, limit),
            )
            return [{"ip": row["ip"], "count": int(row["n"])} for row in cur.fetchall()]

    def confidence_histogram(self, bins: int = 10) -> list[dict[str, Any]]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT confidence FROM predictions WHERE confidence IS NOT NULL AND error IS NULL"
            )
            values = [float(row["confidence"]) for row in cur.fetchall()]
        edges = [i / bins for i in range(bins + 1)]
        histogram = []
        for index in range(bins):
            low, high = edges[index], edges[index + 1]
            count = sum(1 for value in values if low <= value < high or (index == bins - 1 and value == 1.0))
            histogram.append({"bucket": f"{low:.1f}-{high:.1f}", "count": count})
        return histogram

    def prediction_latency(self, limit: int = 5000) -> dict[str, Any]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT latency_ms FROM predictions WHERE latency_ms IS NOT NULL "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            values = sorted(float(row["latency_ms"]) for row in cur.fetchall())
        if not values:
            return {"count": 0, "avg_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None}
        def pct(p: float) -> float:
            index = min(len(values) - 1, max(0, int(round(p * (len(values) - 1)))))
            return round(values[index], 3)
        return {
            "count": len(values),
            "avg_ms": round(sum(values) / len(values), 3),
            "p50_ms": pct(0.50),
            "p95_ms": pct(0.95),
            "max_ms": round(values[-1], 3),
        }

    def model_error_count(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM predictions WHERE error IS NOT NULL")
            return int(cur.fetchone()["n"])

    def prediction_counts(self) -> dict[str, int]:
        with self._cursor() as cur:
            cur.execute("SELECT COALESCE(label, 'UNCLASSIFIED') AS label, COUNT(*) AS n "
                        "FROM predictions GROUP BY label")
            counts = {row["label"]: int(row["n"]) for row in cur.fetchall()}
            cur.execute("SELECT COUNT(*) AS n FROM events")
            total = int(cur.fetchone()["n"])
        counts["UNCLASSIFIED"] = total - sum(
            value for label, value in counts.items() if label != "UNCLASSIFIED"
        )
        return counts

    def dead_letter_count(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM dead_letters")
            return int(cur.fetchone()["n"])

    def query_attacks(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        start: float | None = None,
        end: float | None = None,
    ) -> list[dict[str, Any]]:
        """Events the ML model called malicious or a rule flagged HIGH/CRITICAL."""

        clauses = [
            "(p.is_malicious = 1 OR EXISTS ("
            "SELECT 1 FROM alerts a WHERE a.event_id = e.id AND a.severity IN ('HIGH','CRITICAL')))"
        ]
        params: list[Any] = []
        if severity:
            clauses.append(
                "(UPPER(p.severity) = ? OR EXISTS (SELECT 1 FROM alerts a "
                "WHERE a.event_id = e.id AND UPPER(a.severity) = ?))"
            )
            params.extend([severity.upper(), severity.upper()])
        if start is not None:
            clauses.append("e.ts >= ?")
            params.append(float(start))
        if end is not None:
            clauses.append("e.ts <= ?")
            params.append(float(end))

        sql = (
            EVENT_SELECT
            + " WHERE "
            + " AND ".join(clauses)
            + " ORDER BY e.ts DESC, e.id DESC LIMIT ? OFFSET ?"
        )
        with self._cursor() as cur:
            cur.execute(sql, (*params, limit, offset))
            events = [self._event_row(row) for row in cur.fetchall()]
            for event in events:
                cur.execute(
                    "SELECT rule, category, severity, confidence, explanation, evidence_json, created_at "
                    "FROM alerts WHERE event_id = ? ORDER BY id",
                    (event["id"],),
                )
                event["alerts"] = [self._alert_row(row) for row in cur.fetchall()]
                event["alert_categories"] = sorted({a["category"] for a in event["alerts"]})
        return events

    def count_attacks(
        self,
        *,
        severity: str | None = None,
        start: float | None = None,
        end: float | None = None,
    ) -> int:
        clauses = [
            "(p.is_malicious = 1 OR EXISTS ("
            "SELECT 1 FROM alerts a WHERE a.event_id = e.id AND a.severity IN ('HIGH','CRITICAL')))"
        ]
        params: list[Any] = []
        if severity:
            clauses.append(
                "(UPPER(p.severity) = ? OR EXISTS (SELECT 1 FROM alerts a "
                "WHERE a.event_id = e.id AND UPPER(a.severity) = ?))"
            )
            params.extend([severity.upper(), severity.upper()])
        if start is not None:
            clauses.append("e.ts >= ?")
            params.append(float(start))
        if end is not None:
            clauses.append("e.ts <= ?")
            params.append(float(end))

        with self._cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n FROM events e JOIN predictions p ON p.event_id = e.id "
                "WHERE " + " AND ".join(clauses),
                params,
            )
            return int(cur.fetchone()["n"])

    def replay_event_count(self) -> int:
        """Events written by the replay harness, which tags every record."""

        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM events WHERE raw_json LIKE '%\"_replay\"%'")
            return int(cur.fetchone()["n"])

    def processing_delay(self, limit: int = 200) -> dict[str, Any]:
        """Event-time to database-write delay, in seconds."""

        with self._cursor() as cur:
            cur.execute(
                "SELECT AVG(delay) AS avg_delay, MAX(delay) AS max_delay, COUNT(*) AS n "
                "FROM (SELECT ingested_at - ts AS delay FROM events "
                "WHERE ingested_at >= ts ORDER BY id DESC LIMIT ?)",
                (limit,),
            )
            row = cur.fetchone()
        return {
            "samples": int(row["n"] or 0),
            "avg_delay_s": round(float(row["avg_delay"]), 4) if row["avg_delay"] is not None else None,
            "max_delay_s": round(float(row["max_delay"]), 4) if row["max_delay"] is not None else None,
        }

    def db_status(self) -> dict[str, Any]:
        size = self.db_path.stat().st_size if self.db_path.exists() else 0
        with self._cursor() as cur:
            cur.execute("PRAGMA quick_check")
            check = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) AS n FROM events")
            events = int(cur.fetchone()["n"])
        return {
            "path": str(self.db_path),
            "size_bytes": size,
            "integrity": check,
            "events": events,
            "journal_mode": "wal",
        }

    def alert_counts_by_rule(self, seconds: int = 86400) -> list[dict[str, Any]]:
        since = time.time() - seconds
        with self._cursor() as cur:
            cur.execute(
                "SELECT rule, category, severity, COUNT(*) AS n FROM alerts "
                "WHERE created_at >= ? GROUP BY rule, category, severity ORDER BY n DESC",
                (since,),
            )
            return [
                {
                    "rule": row["rule"],
                    "category": row["category"],
                    "severity": row["severity"],
                    "count": int(row["n"]),
                }
                for row in cur.fetchall()
            ]
