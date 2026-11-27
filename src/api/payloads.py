"""Payload builders shared by the REST routes and the WebSocket ticker.

Keeping one implementation matters: the dashboard merges REST snapshots with the
pushed ``metrics`` frames, so both must expose identical fields.
"""

from __future__ import annotations

from typing import Any


def overview_payload(state: Any) -> dict[str, Any]:
    """Full overview document: DB aggregates, model card and sensor state."""

    data = state.store.overview(state.settings.metrics_window_s)
    data["model"] = {
        "name": state.model.name,
        "version": state.model.version,
        "loaded": state.model.is_loaded,
        "load_error": state.model.load_error,
        "threshold": state.model.metadata.get("threshold"),
        "trained_at": state.model.metadata.get("trained_at"),
        "training_datasets": state.model.metadata.get("training_datasets"),
    }
    sensor = state.service.status() if state.service else {}
    replay_records = state.store.replay_event_count()
    data["sensor"] = {
        "sensor_id": state.settings.sensor_id,
        "mode": "replay" if replay_records else state.settings.sensor_mode,
        "replay_records": replay_records,
        "ingestion_running": sensor.get("ingestion_running", False),
        "remote_ingest_enabled": sensor.get("remote_ingest_enabled", bool(state.settings.api_key)),
        "log_dir_exists": sensor.get("reader", {}).get("log_dir_exists", False),
        "log_file_count": sensor.get("reader", {}).get("log_file_count", 0),
        "seconds_since_event": sensor.get("seconds_since_event"),
        "last_error": sensor.get("last_error"),
    }
    data["websocket"] = state.hub.status()
    data["no_new_events"] = (
        data["seconds_since_last_event"] is None or data["seconds_since_last_event"] > 15
    )
    return data
