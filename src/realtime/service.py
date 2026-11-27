"""Ingestion orchestrator: log tail -> parse -> detect -> predict -> persist -> broadcast."""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

from src.realtime.config import Settings
from src.realtime.detectors import DetectionHit, DetectorEngine, combine_severity
from src.realtime.features import features_from_zeek
from src.realtime.model import ZeekModel
from src.realtime.reader import ZeekLogReader
from src.realtime.store import Store
from src.realtime.zeek_parser import NormalizedEvent

logger = logging.getLogger(__name__)

Publisher = Callable[[dict[str, Any]], None]


class IngestionService:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        model: ZeekModel,
        publisher: Publisher | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.model = model
        self.reader = ZeekLogReader(settings.zeek_log_dir, store, settings.sensor_id)
        self.detectors = DetectorEngine()
        self._publisher = publisher
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        # Serialises the local tailer and remote pushes: the detector engine keeps
        # sliding windows in memory, so only one writer may touch it at a time.
        self._process_lock = threading.Lock()
        self.counters = {
            "lines_processed": 0,
            "events_inserted": 0,
            "duplicates_skipped": 0,
            "predictions": 0,
            "unclassified": 0,
            "alerts": 0,
            "errors": 0,
            "replay_records": 0,
        }
        self.last_poll_at: float | None = None
        self.last_event_at: float | None = None
        self.last_error: str | None = None

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="ndr-ingest", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run(self) -> None:
        last_purge = 0.0
        while not self._stop.is_set():
            try:
                self.process_once()
                if time.time() - last_purge > 3600:
                    removed = self.store.purge_older_than(self.settings.retention_days)
                    if removed:
                        logger.info("Retention purge removed %s events", removed)
                    last_purge = time.time()
                self._persist_status()
            except Exception as error:  # never let the worker die
                self.counters["errors"] += 1
                self.last_error = str(error)
                logger.exception("Ingestion loop error")
            self._stop.wait(self.settings.poll_interval_s)

    # ------------------------------------------------------------------ #
    # one polling cycle (also used directly by tests)
    # ------------------------------------------------------------------ #
    def process_once(self) -> dict[str, int]:
        batch = {"processed": 0, "inserted": 0, "predictions": 0, "alerts": 0, "errors": 0}
        for path, _offset, event in self.reader.read_new():
            batch["processed"] += 1
            try:
                with self._process_lock:
                    result = self._handle_event(path, event)
                for key in ("inserted", "predictions", "alerts"):
                    batch[key] += int(result[key])
            except Exception as error:
                batch["errors"] += 1
                self.counters["errors"] += 1
                self.last_error = str(error)
                logger.exception("Failed to process event %s", event.event_uid)
                self.store.record_dead_letter(
                    str(path), event.source_offset, json.dumps(event.raw, default=str)[:4000], str(error)
                )
        with self._lock:
            self.counters["lines_processed"] += batch["processed"]
        self.last_poll_at = time.time()
        return batch

    def _handle_event(self, path: Path, event: NormalizedEvent) -> dict[str, Any]:
        result: dict[str, Any] = {
            "inserted": 0,
            "predictions": 0,
            "alerts": 0,
            "event_id": None,
            "label": None,
            "severity": None,
        }

        if event.raw.get("_replay"):
            # Replayed held-out flows are labelled in the UI so nobody mistakes
            # them for live capture.
            self.counters["replay_records"] += 1

        feature_map = features_from_zeek(event)
        hits: list[DetectionHit] = self.detectors.observe(event, feature_map)

        prediction = None
        severity: str | None = None
        alert_rows: list[dict[str, Any]] = []

        # One transaction per flow: the dashboard must never observe an event
        # that has no prediction yet, which would show up as a phantom
        # "unclassified" count.
        with self.store.transaction():
            event_id, inserted = self.store.insert_event(event.to_row())
            if not inserted:
                self.counters["duplicates_skipped"] += 1
                result["duplicate"] = True
                return result
            result["inserted"] = 1
            result["event_id"] = event_id
            self.counters["events_inserted"] += 1
            self.last_event_at = time.time()

            if feature_map is None:
                self.counters["unclassified"] += 1
            else:
                if self.model.is_loaded:
                    prediction = self.model.predict(feature_map)
                if prediction is None:
                    reason = self.model.load_error or "model unavailable"
                    self.store.save_prediction(
                        event_id,
                        {
                            "model_name": self.model.name,
                            "model_version": self.model.version,
                            "error": reason,
                            "created_at": time.time(),
                        },
                    )
                    self.counters["unclassified"] += 1
                else:
                    severity = combine_severity(prediction.severity, hits)
                    payload = prediction.to_store_dict()
                    payload["severity"] = severity
                    self.store.save_prediction(event_id, payload)
                    self.counters["predictions"] += 1
                    result["predictions"] = 1

            if hits and severity is None:
                severity = combine_severity(None, hits)

            result["label"] = prediction.label if prediction else None
            result["severity"] = severity

            for hit in hits:
                if self.store.save_alert(event_id, hit.to_dict()):
                    result["alerts"] += 1
                    self.counters["alerts"] += 1
                alert_rows.append(hit.to_dict())

        self._publish_event(event, event_id, prediction, severity, alert_rows)
        return result

    def _publish_event(
        self,
        event: NormalizedEvent,
        event_id: int,
        prediction: Any,
        severity: str | None,
        alerts: list[dict[str, Any]],
    ) -> None:
        if self._publisher is None:
            return
        payload = {
            "id": event_id,
            "event_uid": event.event_uid,
            "ts": event.ts,
            "ingested_at": time.time(),
            "log_type": event.log_type,
            "sensor": event.sensor,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "src_port": event.src_port,
            "dst_port": event.dst_port,
            "proto": event.proto,
            "service": event.service,
            "conn_state": event.conn_state,
            "duration": event.duration,
            "orig_bytes": event.orig_bytes,
            "resp_bytes": event.resp_bytes,
            "orig_pkts": event.orig_pkts,
            "resp_pkts": event.resp_pkts,
            "orig_ip_bytes": event.orig_ip_bytes,
            "resp_ip_bytes": event.resp_ip_bytes,
            "prediction": prediction.label if prediction else None,
            "confidence": prediction.confidence if prediction else None,
            "severity": severity,
            "is_malicious": prediction.is_malicious if prediction else None,
            "explanation": prediction.explanation if prediction else None,
            "latency_ms": prediction.latency_ms if prediction else None,
            "model_name": prediction.model_name if prediction else None,
            "model_version": prediction.model_version if prediction else None,
            "prediction_error": None if prediction else self.model.load_error,
            "threshold": prediction.threshold if prediction else None,
            "alerts": alerts,
            "raw": event.raw,
        }
        try:
            self._publisher({"type": "event", "event": payload})
        except Exception:  # broadcast must never break ingestion
            logger.warning("Failed to publish event %s", event_id, exc_info=True)

    def process_remote_event(self, event: NormalizedEvent) -> dict[str, Any]:
        """Score an event pushed by a remote sensor (same path as a tailed line).

        Runs whether or not the local log tailer is enabled, so a hosted API can
        accept authenticated pushes while the sensor runs on another machine.
        """

        with self._process_lock:
            result = self._handle_event(Path(event.source_file), event)
        with self._lock:
            self.counters["lines_processed"] += 1
        self.last_poll_at = time.time()
        return result

    # ------------------------------------------------------------------ #
    # status
    # ------------------------------------------------------------------ #
    def _persist_status(self) -> None:
        try:
            self.store.set_service_state(
                "sensor_status",
                {
                    "sensor_id": self.settings.sensor_id,
                    "sensor_mode": self.settings.sensor_mode,
                    "running": self.running,
                    "counters": self.counters,
                    "last_poll_at": self.last_poll_at,
                    "last_event_at": self.last_event_at,
                    "last_error": self.last_error,
                    "reader": self.reader.sensor_health(),
                },
            )
        except Exception:  # pragma: no cover - status is best effort
            logger.debug("Could not persist sensor status", exc_info=True)

    def status(self) -> dict[str, Any]:
        reader_health = self.reader.sensor_health()
        now = time.time()
        last_event_ts = self.last_event_at
        return {
            "sensor_id": self.settings.sensor_id,
            "sensor_mode": self.settings.sensor_mode,
            "ingestion_running": self.running,
            "ingest_enabled": self.settings.ingest_enabled,
            "remote_ingest_enabled": bool(self.settings.api_key),
            "poll_interval_s": self.settings.poll_interval_s,
            "counters": dict(self.counters),
            "last_poll_at": self.last_poll_at,
            "last_event_at": last_event_ts,
            "seconds_since_event": round(now - last_event_ts, 1) if last_event_ts else None,
            "last_error": self.last_error,
            "reader": reader_health,
            "detectors": {
                "rules": [
                    "port_scan_sweep",
                    "host_sweep",
                    "syn_flood",
                    "auth_brute_force",
                    "c2_beaconing",
                    "outbound_exfiltration",
                    "large_outbound_flow",
                    "connection_failure_ratio",
                    "exposed_high_risk_service",
                    "dns_tunneling",
                ]
            },
        }
