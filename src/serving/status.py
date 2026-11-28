"""Composed status for the serving app.

Everything here is derived from live objects: loaded predictors, the SQLite
files, the ingestion task and the environment. Nothing is hardcoded, so a broken
deployment reports ``degraded`` with the reason instead of a green checkmark.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from src.serving.predictor import predictor_state
from src.serving.security import auth_summary
from src.serving.zeek_predictor import zeek_model_state

APP_NAME = "nids-serving"
APP_VERSION = "0.1.0"


def database_state(path: Path) -> dict[str, Any]:
    resolved = Path(path)
    state: dict[str, Any] = {"path": str(resolved), "exists": resolved.exists(), "integrity": "unavailable"}
    if not resolved.exists():
        return state
    try:
        with sqlite3.connect(resolved) as conn:
            state["integrity"] = conn.execute("PRAGMA integrity_check").fetchone()[0]
            state["events"] = conn.execute("SELECT COUNT(*) FROM zeek_events").fetchone()[0]
            state["detections"] = conn.execute("SELECT COUNT(*) FROM zeek_detections").fetchone()[0]
    except sqlite3.Error as exc:
        state["integrity"] = f"error: {exc}"
    return state


def ingestion_state(state: Any) -> dict[str, Any]:
    settings = state.settings
    service = getattr(state, "zeek_service", None)
    if service is not None:
        return service.status()
    log_dir = Path(settings.zeek_log_dir)
    return {
        "enabled": bool(settings.zeek_enabled),
        "running": False,
        "log_dir": str(log_dir),
        "log_dir_exists": log_dir.exists(),
        "log_file_count": len(list(log_dir.glob("*.log"))) if log_dir.exists() else 0,
        "sensor_id": settings.zeek_sensor_id,
        "log_types": [t for t in str(settings.zeek_log_types).split(",") if t],
        "poll_interval_s": settings.zeek_poll_interval,
    }


def health_payload(state: Any) -> dict[str, Any]:
    """Full liveness document. Safe to expose: no event contents, no secrets."""

    settings = state.settings
    cicids = predictor_state()
    zeek = zeek_model_state()
    database = database_state(settings.db_path)
    ingestion = ingestion_state(state)

    scoring_available = bool(cicids["loaded"] or zeek["loaded"])
    database_ok = database.get("integrity") == "ok"
    status = "ok" if scoring_available and database_ok else "degraded"
    degraded = [
        name
        for name, ok in (
            ("cicids_model", cicids["loaded"]),
            ("zeek_model", zeek["loaded"]),
            ("database", database_ok),
        )
        if not ok
    ]

    payload: dict[str, Any] = {
        "status": status,
        "degraded_components": degraded,
        "app": APP_NAME,
        "version": APP_VERSION,
        "components": {
            "auth": auth_summary(settings),
            "cicids_model": cicids,
            "zeek_model": zeek,
            "database": database,
            "zeek_ingestion": ingestion,
        },
    }
    # Backwards-compatible flat keys for existing clients.
    if cicids["loaded"]:
        from src.serving.predictor import get_predictor

        predictor = get_predictor()
        payload.update(
            {
                "model": type(predictor.model).__name__,
                "input_features": len(predictor.feature_order),
                "model_features": len(predictor.model_features) if predictor.model_features else len(predictor.feature_order),
                "classes": predictor.classes,
            }
        )
    else:
        payload["model"] = None
    return payload


def readiness(state: Any) -> tuple[bool, dict[str, Any]]:
    """Readiness for the mode this process is deployed in.

    The service is ready when it can persist events and at least one scorer is
    usable: the Zeek model when local ingestion is enabled, otherwise either
    model (a Zeek-only deployment does not need the CICIDS artefacts).
    """

    payload = health_payload(state)
    components = payload["components"]
    database_ok = components["database"].get("integrity") == "ok"
    zeek_ok = bool(components["zeek_model"]["loaded"])
    cicids_ok = bool(components["cicids_model"]["loaded"])
    ingestion_enabled = bool(components["zeek_ingestion"]["enabled"])
    scorer_ok = zeek_ok if ingestion_enabled else (zeek_ok or cicids_ok)
    ready = database_ok and scorer_ok
    reasons: list[str] = []
    if not database_ok:
        reasons.append(f"database not usable at {components['database']['path']}")
    if not scorer_ok:
        reasons.append("no scoring model could be loaded")
    return ready, {"ready": ready, "reasons": reasons, "components": components}
