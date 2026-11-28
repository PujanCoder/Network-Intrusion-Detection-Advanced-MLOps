"""Service layer behind the SOC dashboard.

The routes stay thin and this module owns the composition rules: what counts as
an event, how a rate is measured, which model served a detection and what a
severity means. Anything not stored is reported as unavailable rather than
guessed, so the dashboard can say "not recorded" instead of inventing a number.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from src.serving.predictor import predictor_state
from src.serving.soc_store import SEVERITY_POLICY, DetectionFilters, SocStore
from src.serving.status import (
    APP_NAME,
    APP_VERSION,
    build_info,
    database_state,
    health_payload,
    ingestion_state,
)
from src.serving.zeek_predictor import zeek_model_state

ZEEK_NOTES = [
    "Trained on 300 synthetic connection records; predictions are experimental, not threat intelligence.",
    "Labels come from that synthetic corpus; treat them as a wiring test for the pipeline.",
]
CICIDS_NOTES = [
    "CICIDS2017 flow classifier. Two classes: BENIGN and DDoS.",
    "In-distribution evaluation only; cross-dataset transfer is weak.",
]


def broadcast_detection(state: Any, source: str, det_id: int) -> None:
    """Push a freshly stored detection to every connected dashboard.

    Called from ingestion handlers (sync and async); ``publish_threadsafe`` moves
    the coroutine onto the app loop, so the caller never blocks on a slow client.
    """

    if not det_id or state.hub.client_count == 0:
        return
    record = state.soc_store.get_detection(source, det_id)
    if record:
        state.hub.publish_threadsafe({"type": "event", "event": record, "server_time": time.time()})


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _seconds_since(value: str | None, now: float) -> float | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, now - parsed.timestamp())


def model_payloads(store: SocStore) -> dict[str, dict[str, Any]]:
    """Both models with their real runtime counters, never a shared bucket."""

    cicids = predictor_state()
    zeek = zeek_model_state()
    runtime = store.model_runtime()

    cicids_names: list[str] | None = None
    if cicids["loaded"]:
        from src.serving.predictor import get_predictor

        predictor = get_predictor()
        cicids_names = list(predictor.feature_order)

    zeek_names: list[str] | None = None
    if zeek["loaded"]:
        from src.serving.zeek_predictor import get_zeek_predictor

        predictor = get_zeek_predictor()
        zeek_names = list(predictor.feature_names) if predictor else None

    return {
        "cicids": {
            "key": "cicids",
            "name": "CICIDS2017 batch flow classifier",
            "task": "Flow-level binary classification (BENIGN / DDoS) from CICIDS2017 features.",
            "loaded": bool(cicids["loaded"]),
            "error": cicids["error"],
            "error_kind": cicids["error_kind"],
            "estimator": cicids["estimator"],
            "version": cicids["version"],
            "trained_at": cicids["trained_at"],
            "loaded_at": cicids["loaded_at"],
            "artifact": cicids["artifacts"]["model"] if cicids.get("artifacts") else None,
            "schema": {
                "schema_version": "cicids2017_flow_v1",
                "features": cicids["features"],
                "model_features": cicids["model_features"],
                "feature_names": cicids_names,
            },
            "classes": cicids["classes"],
            "experimental": False,
            "notes": CICIDS_NOTES,
            "runtime": runtime["cicids"],
            "latency": {
                "available": False,
                "reason": "The pipeline does not persist per-prediction latency; measuring it would require instrumenting the scorer.",
            },
        },
        "zeek": {
            "key": "zeek",
            "name": "Zeek connection classifier",
            "task": "Per-record classification of Zeek conn.log fields into synthetic attack labels.",
            "loaded": bool(zeek["loaded"]),
            "error": zeek["error"],
            "error_kind": "missing" if not zeek["exists"] else zeek["error"],
            "estimator": "RandomForestClassifier (synthetic training set)",
            "version": zeek["version"],
            "trained_at": None,
            "loaded_at": zeek["loaded_at"],
            "artifact": {"path": zeek["path"], "exists": zeek["exists"], "bytes": None},
            "schema": {
                "schema_version": zeek["schema_version"],
                "features": zeek["features"],
                "model_features": zeek["features"],
                "feature_names": zeek_names,
                "threshold": zeek["threshold"],
            },
            "classes": zeek["classes"],
            "experimental": True,
            "notes": ZEEK_NOTES,
            "runtime": runtime["zeek"],
            "latency": {
                "available": False,
                "reason": "The pipeline does not persist per-prediction latency; measuring it would require instrumenting the scorer.",
            },
        },
    }


def sensor_payload(state: Any) -> dict[str, Any]:
    store: SocStore = state.soc_store
    settings = state.settings
    sensors = store.sensors(stale_after_s=settings.sensor_stale_after_s)
    totals = store.totals()
    for sensor in sensors:
        sensor["is_local_ingestion"] = sensor["sensor_id"] == settings.zeek_sensor_id
    ingestion = ingestion_state(state)
    return {
        "generated_at": _iso_now(),
        "stale_after_s": settings.sensor_stale_after_s,
        "summary": {
            "total": len(sensors),
            "online": sum(1 for s in sensors if s["status"] == "online"),
            "offline": sum(1 for s in sensors if s["status"] == "offline"),
            "unknown": sum(1 for s in sensors if s["status"] == "unknown"),
            "events": totals["events"],
            "dead_letters": totals["dead_letters"],
        },
        "sensors": sensors,
        "ingestion": ingestion,
        "expected": {
            "sensor_id": settings.zeek_sensor_id,
            "mode": "remote" if not settings.zeek_enabled else "local",
            "local_ingestion_enabled": bool(settings.zeek_enabled),
            "log_dir": str(settings.zeek_log_dir),
            "log_types": [t for t in str(settings.zeek_log_types).split(",") if t],
        },
        "counters": totals,
    }


def overview_payload(state: Any, *, window_s: int | None = None) -> dict[str, Any]:
    store: SocStore = state.soc_store
    settings = state.settings
    now = time.time()
    window = int(window_s or settings.metrics_window_s)
    filters = DetectionFilters()

    totals = store.totals()
    counts = store._counts(filters)
    sensors = store.sensors(stale_after_s=settings.sensor_stale_after_s)
    rate_filters = DetectionFilters(start=datetime.fromtimestamp(now - settings.rate_window_s, timezone.utc).isoformat())
    rate_counts = store._counts(rate_filters)
    bucket_s = max(5, min(300, window // 60))
    recent, _ = store.list_detections(filters, limit=12)

    last_event_age = _seconds_since(totals["last_event_ts"], now)
    no_new_events = totals["events"] == 0
    return {
        "generated_at": _iso_now(),
        "server_time": now,
        "window_s": window,
        "app": {"name": APP_NAME, "version": APP_VERSION, "build": build_info()},
        "totals": {
            **counts,
            "events": totals["events"],
            "dead_letters": totals["dead_letters"],
            "by_log_type": totals["by_log_type"],
        },
        "rates": {
            "window_s": settings.rate_window_s,
            "events_per_second": round(rate_counts["detections"] / settings.rate_window_s, 4),
            "attacks_per_second": round(rate_counts["attacks"] / settings.rate_window_s, 4),
        },
        "activity": {
            "last_event_ts": totals["last_event_ts"],
            "seconds_since_event": None if last_event_age is None else round(last_event_age, 1),
            "last_detection_ts": counts["last_detection_ts"],
            "no_new_events": no_new_events,
            "message": (
                "No new network events received."
                if no_new_events
                else f"Last event {int(last_event_age or 0)}s ago"
            ),
        },
        "sensors": {
            "total": len(sensors),
            "online": sum(1 for s in sensors if s["status"] == "online"),
            "offline": sum(1 for s in sensors if s["status"] == "offline"),
            "unknown": sum(1 for s in sensors if s["status"] == "unknown"),
            "stale_after_s": settings.sensor_stale_after_s,
            "items": sensors,
        },
        "models": model_payloads(store),
        "severity_policy": SEVERITY_POLICY,
        "series": store.series(filters, window_s=window, bucket_s=bucket_s),
        "bucket_s": bucket_s,
        "distributions": {
            "labels": store.distribution(filters, "label"),
            "protocols": store.distribution(filters, "proto"),
            "severities": store.distribution(filters, "severity"),
            "log_types": store.distribution(filters, "log_type"),
            "sources": store.distribution(filters, "source"),
            "confidence": store.confidence_histogram(filters),
            "top_src_ips": store.top_ips(filters, "src_ip"),
            "top_dst_ips": store.top_ips(filters, "dst_ip"),
        },
        "recent": recent,
    }


def system_payload(state: Any, *, auth_method: str | None = None) -> dict[str, Any]:
    health = health_payload(state)
    return {
        "generated_at": _iso_now(),
        "server_time": time.time(),
        "status": health["status"],
        "degraded_components": health["degraded_components"],
        "app": {"name": APP_NAME, "version": APP_VERSION},
        "build": health["build"],
        "uptime_s": round(time.time() - getattr(state, "started_at", time.time()), 1),
        "components": health["components"],
        "database": database_state(state.settings.db_path),
        "websocket": state.hub.status(),
        "auth": {**health["components"]["auth"], "request_authenticated_by": auth_method},
        "endpoints": {
            "health": "/api/v1/health",
            "readiness": "/api/v1/ready",
            "metrics": "/api/v1/metrics/overview",
            "detections": "/api/v1/detections",
            "alerts": "/ws/alerts",
        },
    }
