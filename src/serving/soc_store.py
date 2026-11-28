"""Database-backed aggregations for the SOC dashboard.

Everything the dashboard renders comes from here: SQL over the two tables the
ingestion pipelines already write (``zeek_events`` + ``zeek_detections`` for the
live sensor, ``detections`` for CICIDS flow scoring). Nothing is cached,
sampled or synthesised, so an idle deployment shows zeros and an empty table.

Two derived values need explaining because no table stores them:

``severity``
    The models emit a label and a confidence, not a severity. The dashboard
    needs one for triage, so ``severity_of`` applies a fixed, documented band
    (:data:`SEVERITY_POLICY`) and the API reports ``severity_source`` next to
    it so nobody mistakes a rule for model output.

``detection_rate``
    Attacks divided by scored records. Records the model could not score
    (``status != 'scored'``) are excluded from the denominator and reported
    separately as ``unclassified``.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SEVERITY_POLICY = {
    "source": "rule:confidence-band-v1",
    "description": (
        "Model output is (label, confidence). Severity bands are a triage rule applied "
        "on top: records the model could not score stay UNKNOWN; scored non-attacks are "
        "INFO; attacks are CRITICAL >= 0.90, HIGH >= 0.75, MEDIUM >= 0.50, otherwise LOW."
    ),
    "bands": [
        {"severity": "UNKNOWN", "attack": None, "min_confidence": 0.0},
        {"severity": "CRITICAL", "attack": True, "min_confidence": 0.9},
        {"severity": "HIGH", "attack": True, "min_confidence": 0.75},
        {"severity": "MEDIUM", "attack": True, "min_confidence": 0.5},
        {"severity": "LOW", "attack": True, "min_confidence": 0.0},
        {"severity": "INFO", "attack": False, "min_confidence": 0.0},
    ],
}

SEVERITY_SQL = (
    "CASE WHEN status != 'scored' THEN 'UNKNOWN'"
    " WHEN is_attack = 0 THEN 'INFO'"
    " WHEN confidence >= 0.9 THEN 'CRITICAL'"
    " WHEN confidence >= 0.75 THEN 'HIGH'"
    " WHEN confidence >= 0.5 THEN 'MEDIUM'"
    " ELSE 'LOW' END"
)

# Both detection sources are projected onto one row shape so the dashboard can
# filter, sort and paginate them together. `is_attack` and `confidence` keep
# their stored meaning; everything else is evidence or context.
_UNION = """
SELECT 'zeek' AS source, d.id AS det_id, d.event_id AS event_id, d.ts AS ts,
       d.log_type AS log_type, d.sensor_id AS sensor_id,
       d.src_ip AS src_ip, d.src_port AS src_port, d.dst_ip AS dst_ip, d.dst_port AS dst_port,
       d.proto AS proto, d.service AS service,
       d.label AS label, d.is_attack AS is_attack, d.confidence AS confidence,
       d.status AS status, d.reason AS reason, d.model_schema_version AS model_schema,
       d.probabilities_json AS probabilities_json, d.raw_event_json AS raw_json,
       json_extract(e.normalized_json, '$.conn_state') AS conn_state,
       json_extract(e.normalized_json, '$.duration') AS duration,
       json_extract(e.normalized_json, '$.orig_bytes') AS orig_bytes,
       json_extract(e.normalized_json, '$.resp_bytes') AS resp_bytes,
       json_extract(e.normalized_json, '$.orig_pkts') AS orig_pkts,
       json_extract(e.normalized_json, '$.resp_pkts') AS resp_pkts,
       e.severity AS event_severity
  FROM zeek_detections d
  LEFT JOIN zeek_events e ON e.event_id = d.event_id
UNION ALL
SELECT 'cicids' AS source, id AS det_id, NULL AS event_id, ts AS ts,
       'flow' AS log_type, NULL AS sensor_id,
       src_ip, src_port, dst_ip, dst_port, proto, NULL AS service,
       label, is_attack, confidence, 'scored' AS status, NULL AS reason,
       'cicids_flow_v1' AS model_schema, NULL AS probabilities_json, flow_json AS raw_json,
       NULL, NULL, NULL, NULL, NULL, NULL, NULL
  FROM detections
"""

_MODEL_NAMES = {
    "zeek": {"name": "zeek-conn-v1", "task": "live Zeek connection classification", "experimental": True},
    "cicids": {"name": "cicids2017-ids", "task": "CICIDS2017 flow classification", "experimental": False},
}

SORTS = {"ts_desc": "ts DESC, source DESC, det_id DESC", "ts_asc": "ts ASC, source ASC, det_id ASC"}


def severity_of(is_attack: Any, confidence: Any, *, scored: bool = True) -> str:
    """Apply :data:`SEVERITY_POLICY` to one record."""

    if not scored:
        return "UNKNOWN"
    if not is_attack:
        return "INFO"
    value = float(confidence) if confidence is not None else 0.0
    if value >= 0.9:
        return "CRITICAL"
    if value >= 0.75:
        return "HIGH"
    if value >= 0.5:
        return "MEDIUM"
    return "LOW"


def _iso(value: Any) -> str | None:
    """Normalise a stored timestamp to UTC ISO-8601 (strings sort correctly)."""

    if value in (None, ""):
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return str(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class DetectionFilters:
    """Validated query filters. ``sources`` empty means both sources."""

    sources: tuple[str, ...] = ("zeek", "cicids")
    label: str | None = None
    severity: str | None = None
    status: str | None = None
    sensor_id: str | None = None
    model: str | None = None
    search: str | None = None
    start: str | None = None
    end: str | None = None
    only_attacks: bool = False

    def where(self) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if self.label:
            clauses.append("UPPER(label) = UPPER(?)")
            params.append(self.label)
        if self.status:
            clauses.append("status = ?")
            params.append(self.status)
        if self.sensor_id:
            clauses.append("sensor_id = ?")
            params.append(self.sensor_id)
        if self.model:
            clauses.append("source = ?")
            params.append(self.model)
        if self.severity:
            clauses.append(f"({SEVERITY_SQL}) = ?")
            params.append(self.severity.upper())
        if self.only_attacks:
            clauses.append("is_attack = 1")
        if self.search:
            like = f"%{self.search}%"
            clauses.append(
                "(src_ip LIKE ? OR dst_ip LIKE ? OR label LIKE ? OR service LIKE ? OR sensor_id LIKE ?)"
            )
            params.extend([like] * 5)
        if self.start:
            clauses.append("ts >= ?")
            params.append(self.start)
        if self.end:
            clauses.append("ts <= ?")
            params.append(self.end)
        sql = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return sql, params


class SocStore:
    """Read-only aggregations over the serving database.

    A read-only connection per call keeps the dashboard from ever holding a
    write lock the ingestion path needs.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    @contextmanager
    def _read(self):
        """Short-lived read connection: never holds a lock, always closed."""

        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            with self._lock:
                yield conn
        finally:
            conn.close()

    def _source_scope(self, sources: tuple[str, ...]) -> str:
        """SQL that restricts the union to the requested sources."""

        allowed = [source for source in ("zeek", "cicids") if source in sources] or ["zeek", "cicids"]
        if len(allowed) == 2:
            return _UNION
        return f"SELECT * FROM ({_UNION}) WHERE source = '{allowed[0]}'"

    # -- records ----------------------------------------------------------- #
    def _record(self, row: sqlite3.Row, *, detail: bool = False) -> dict[str, Any]:
        raw = json.loads(row["raw_json"] or "{}")
        record: dict[str, Any] = {
            "id": f"{row['source']}:{row['det_id']}",
            "source": row["source"],
            "ts": _iso(row["ts"]),
            "sensor_id": row["sensor_id"],
            "log_type": row["log_type"],
            "src_ip": row["src_ip"],
            "src_port": row["src_port"],
            "dst_ip": row["dst_ip"],
            "dst_port": row["dst_port"],
            "proto": row["proto"],
            "service": row["service"],
            "conn_state": row["conn_state"],
            "duration": row["duration"],
            "orig_bytes": row["orig_bytes"],
            "resp_bytes": row["resp_bytes"],
            "orig_pkts": row["orig_pkts"],
            "resp_pkts": row["resp_pkts"],
            "label": row["label"],
            "is_attack": bool(row["is_attack"]),
            "confidence": row["confidence"],
            "status": row["status"],
            "severity": severity_of(row["is_attack"], row["confidence"], scored=row["status"] == "scored"),
            "severity_source": SEVERITY_POLICY["source"],
            "model": {
                "source": row["source"],
                "name": _MODEL_NAMES[row["source"]]["name"],
                "schema": row["model_schema"],
                "experimental": _MODEL_NAMES[row["source"]]["experimental"],
            },
            "explanation": self._explanation(row),
        }
        if detail:
            record["probabilities"] = json.loads(row["probabilities_json"] or "null")
            # Zeek detections store the whole envelope; show the original record and
            # keep the envelope separately so the drawer can print both.
            if isinstance(raw.get("raw"), dict):
                record["raw"] = raw["raw"]
                record["envelope"] = {k: v for k, v in raw.items() if k != "raw"}
            else:
                record["raw"] = raw
            record["event_severity"] = row["event_severity"]
            record["reason"] = row["reason"]
        return record

    @staticmethod
    def _explanation(row: sqlite3.Row) -> str:
        model = _MODEL_NAMES[row["source"]]["name"]
        if row["source"] == "zeek":
            parts = [f"{model} scored this {row['log_type']} record as {row['label']}"]
            if row["confidence"] is not None:
                parts.append(f"confidence {float(row['confidence']):.3f}")
        else:
            parts = [f"{model} scored this CICIDS flow as {row['label']}"]
            if row["confidence"] is not None:
                parts.append(f"confidence {float(row['confidence']):.3f}")
        if row["status"] and row["status"] != "scored":
            parts.append(f"status {row['status']}")
        if row["reason"]:
            parts.append(str(row["reason"]))
        return "; ".join(parts)

    def list_detections(
        self, filters: DetectionFilters, *, limit: int = 50, offset: int = 0, sort: str = "ts_desc"
    ) -> tuple[list[dict[str, Any]], int]:
        where, params = filters.where()
        order = SORTS.get(sort, SORTS["ts_desc"])
        scope = self._source_scope(filters.sources)
        with self._read() as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM ({scope}){where}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM ({scope}){where} ORDER BY {order} LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
        return [self._record(row) for row in rows], int(total)

    def get_detection(self, source: str, det_id: int) -> dict[str, Any] | None:
        scope = self._source_scope((source,))
        with self._read() as conn:
            row = conn.execute(f"SELECT * FROM ({scope}) WHERE source = ? AND det_id = ?", (source, det_id)).fetchone()
        return self._record(row, detail=True) if row else None

    def iter_detections(self, filters: DetectionFilters, *, sort: str = "ts_desc", cap: int = 100_000) -> Iterator[dict[str, Any]]:
        where, params = filters.where()
        order = SORTS.get(sort, SORTS["ts_desc"])
        scope = self._source_scope(filters.sources)
        conn = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.execute(f"SELECT * FROM ({scope}){where} ORDER BY {order} LIMIT ?", [*params, cap])
            for row in cursor:
                yield self._record(row, detail=True)
        finally:
            conn.close()

    # -- aggregates -------------------------------------------------------- #
    def _counts(self, filters: DetectionFilters) -> dict[str, Any]:
        where, params = filters.where()
        scope = self._source_scope(filters.sources)
        sql = f"""
        SELECT COUNT(*) AS detections,
               COALESCE(SUM(is_attack = 1), 0) AS attacks,
               COALESCE(SUM(is_attack = 0), 0) AS benign,
               COALESCE(SUM(status = 'scored'), 0) AS scored,
               COALESCE(SUM(status != 'scored'), 0) AS unclassified,
               MAX(ts) AS last_ts
          FROM ({scope}){where}
        """
        with self._read() as conn:
            row = dict(conn.execute(sql, params).fetchone())
            by_source = {
                r["source"]: r["c"]
                for r in conn.execute(f"SELECT source, COUNT(*) c FROM ({scope}){where} GROUP BY source", params)
            }
        detections = int(row["detections"] or 0)
        scored = int(row["scored"] or 0)
        attacks = int(row["attacks"] or 0)
        # Unscored rows are stored with is_attack = 0; they are not "benign", they
        # are unknown. Benign therefore counts scored records the model cleared.
        benign = max(0, scored - attacks)
        return {
            "detections": detections,
            "attacks": attacks,
            "benign": benign,
            "scored": scored,
            "unclassified": int(row["unclassified"] or 0),
            "detection_rate": round(attacks / scored, 4) if scored else None,
            "last_detection_ts": _iso(row["last_ts"]),
            "by_source": by_source,
        }

    def distribution(self, filters: DetectionFilters, column: str) -> list[dict[str, Any]]:
        expression = SEVERITY_SQL if column == "severity" else column
        where, params = filters.where()
        scope = self._source_scope(filters.sources)
        sql = (
            f"SELECT {expression} AS label, COUNT(*) AS count FROM ({scope}){where} "
            f"GROUP BY 1 ORDER BY count DESC, label ASC"
        )
        with self._read() as conn:
            return [{"label": str(r["label"]), "count": int(r["count"])} for r in conn.execute(sql, params)]

    def confidence_histogram(self, filters: DetectionFilters, bucket: float = 0.1) -> list[dict[str, Any]]:
        where, params = filters.where()
        scope = self._source_scope(filters.sources)
        with self._read() as conn:
            rows = conn.execute(
                f"SELECT confidence FROM ({scope}){where} AND confidence IS NOT NULL"
                if where
                else f"SELECT confidence FROM ({scope}) WHERE confidence IS NOT NULL",
                params,
            ).fetchall()
        buckets = [f"{i / 10:.1f}–{(i + 1) / 10:.1f}" for i in range(10)]
        tally = dict.fromkeys(buckets, 0)
        for row in rows:
            value = min(max(float(row["confidence"]), 0.0), 0.9999)
            tally[buckets[int(value / bucket)]] += 1
        return [{"bucket": name, "count": count} for name, count in tally.items()]

    def top_ips(self, filters: DetectionFilters, column: str, limit: int = 10) -> list[dict[str, Any]]:
        if column not in ("src_ip", "dst_ip"):
            raise ValueError("column must be src_ip or dst_ip")
        where, params = filters.where()
        scope = self._source_scope(filters.sources)
        joiner = f"{where} AND {column} IS NOT NULL" if where else f" WHERE {column} IS NOT NULL"
        sql = (
            f"SELECT {column} AS ip, COUNT(*) AS count FROM ({scope}){joiner} "
            f"GROUP BY 1 ORDER BY count DESC LIMIT ?"
        )
        with self._read() as conn:
            return [{"ip": r["ip"], "count": int(r["count"])} for r in conn.execute(sql, [*params, limit])]

    def series(self, filters: DetectionFilters, *, window_s: int, bucket_s: int = 60, max_buckets: int = 120) -> list[dict[str, Any]]:
        """Bucketed event/prediction/attack counts for the requested window.

        Buckets are computed in Python because timestamps are stored as ISO text
        with offsets; the SQL side only filters, which keeps it index-friendly.
        """

        bucket_s = max(5, min(int(bucket_s), window_s))
        now = datetime.now(timezone.utc)
        start = now - timedelta(seconds=window_s)
        buckets = int(min(max_buckets, max(1, window_s // bucket_s)))
        base = int(now.timestamp()) - (int(now.timestamp()) % bucket_s)
        edges = [base - (buckets - 1 - i) * bucket_s for i in range(buckets)]
        tally = {edge: {"t": edge, "events": 0, "predictions": 0, "attacks": 0, "bytes": 0} for edge in edges}

        where, params = filters.where()
        scope = self._source_scope(filters.sources)
        time_clause = "ts >= ?" if where else ""
        sql = f"SELECT ts, is_attack, status, orig_bytes, resp_bytes FROM ({scope}){where}{' AND ' if time_clause else ' WHERE '}{time_clause or 'ts >= ?'}"
        with self._read() as conn:
            rows = conn.execute(sql, [*params, start.isoformat()]).fetchall()

        for row in rows:
            ts = _iso(row["ts"])
            if not ts:
                continue
            epoch = int(datetime.fromisoformat(ts).timestamp())
            if epoch < edges[0]:
                continue
            slot = edges[0] + ((epoch - edges[0]) // bucket_s) * bucket_s
            entry = tally.get(slot)
            if entry is None:
                continue
            entry["predictions"] += 1
            entry["attacks"] += int(bool(row["is_attack"]))
            entry["bytes"] += int(row["orig_bytes"] or 0) + int(row["resp_bytes"] or 0)
        return list(tally.values())

    # -- sensors and health ------------------------------------------------ #
    def sensors(self, *, stale_after_s: int) -> list[dict[str, Any]]:
        """Per-sensor counters plus an explicit liveness verdict.

        A sensor is online only when the deployment heard from it recently; a
        row in the database proves it existed, not that it is alive.
        """

        now = datetime.now(timezone.utc)
        with self._read() as conn:
            rows = conn.execute(
                """
                SELECT s.sensor_id, s.last_seen_ts, s.last_ingested_at, s.last_error,
                       s.events_ingested, s.events_duplicate, s.dead_letters,
                       (SELECT COUNT(*) FROM zeek_events e WHERE e.sensor_id = s.sensor_id) AS events,
                       (SELECT COUNT(*) FROM zeek_detections d WHERE d.sensor_id = s.sensor_id) AS detections,
                       (SELECT COUNT(*) FROM zeek_detections d WHERE d.sensor_id = s.sensor_id AND d.status='scored') AS scored,
                       (SELECT COUNT(*) FROM zeek_detections d WHERE d.sensor_id = s.sensor_id AND d.status!='scored') AS unclassified,
                       (SELECT COUNT(*) FROM zeek_detections d WHERE d.sensor_id = s.sensor_id AND d.is_attack=1) AS attacks,
                       (SELECT COUNT(*) FROM zeek_dead_letters dl WHERE dl.sensor_id = s.sensor_id) AS dead_letter_rows
                  FROM zeek_ingestion_status s
                 ORDER BY s.updated_at DESC
                """
            ).fetchall()

        result = []
        for row in rows:
            last = _iso(row["last_ingested_at"])
            age = None
            if last:
                age = max(0.0, (now - datetime.fromisoformat(last)).total_seconds())
            if age is None:
                status, reason = "unknown", "no ingestion recorded"
            elif age <= stale_after_s:
                status, reason = "online", f"ingested an event {int(age)}s ago"
            else:
                status, reason = "offline", f"silent for {int(age)}s (threshold {stale_after_s}s)"
            result.append(
                {
                    "sensor_id": row["sensor_id"],
                    "status": status,
                    "status_reason": reason,
                    "seconds_since_ingest": None if age is None else round(age, 1),
                    "last_seen_ts": _iso(row["last_seen_ts"]),
                    "last_ingested_at": last,
                    "last_error": row["last_error"],
                    "events": int(row["events"]),
                    "detections": int(row["detections"]),
                    "scored": int(row["scored"]),
                    "unclassified": int(row["unclassified"]),
                    "attacks": int(row["attacks"]),
                    "duplicates": int(row["events_duplicate"]),
                    "dead_letters": max(int(row["dead_letters"]), int(row["dead_letter_rows"])),
                }
            )
        return result

    def totals(self) -> dict[str, Any]:
        with self._read() as conn:
            events = conn.execute("SELECT COUNT(*) c FROM zeek_events").fetchone()["c"]
            by_log_type = {
                r["log_type"]: r["c"]
                for r in conn.execute("SELECT log_type, COUNT(*) c FROM zeek_events GROUP BY log_type")
            }
            dead_letters = conn.execute("SELECT COUNT(*) c FROM zeek_dead_letters").fetchone()["c"]
            last_event = conn.execute("SELECT MAX(ts) ts FROM zeek_events").fetchone()["ts"]
        return {
            "events": int(events),
            "by_log_type": by_log_type,
            "dead_letters": int(dead_letters),
            "last_event_ts": _iso(last_event),
        }

    def model_runtime(self) -> dict[str, dict[str, Any]]:
        """Per-source inference counters and the most recent inference."""

        with self._read() as conn:
            zeek = conn.execute(
                """
                SELECT COUNT(*) total, MAX(created_at) last_ts,
                       COALESCE(SUM(status='scored'),0) scored,
                       COALESCE(SUM(status!='scored'),0) unclassified
                  FROM zeek_detections
                """
            ).fetchone()
            cicids = conn.execute("SELECT COUNT(*) total, MAX(ts) last_ts FROM detections").fetchone()
            zeek_labels = {
                r["label"]: r["c"]
                for r in conn.execute("SELECT label, COUNT(*) c FROM zeek_detections GROUP BY label ORDER BY c DESC")
            }
            cicids_labels = {
                r["label"]: r["c"]
                for r in conn.execute("SELECT label, COUNT(*) c FROM detections GROUP BY label ORDER BY c DESC")
            }
        return {
            "zeek": {
                "predictions": int(zeek["total"]),
                "scored": int(zeek["scored"]),
                "unclassified": int(zeek["unclassified"]),
                "last_inference_ts": _iso(zeek["last_ts"]),
                "label_counts": zeek_labels,
            },
            "cicids": {
                "predictions": int(cicids["total"]),
                "scored": int(cicids["total"]),
                "unclassified": 0,
                "last_inference_ts": _iso(cicids["last_ts"]),
                "label_counts": cicids_labels,
            },
        }
