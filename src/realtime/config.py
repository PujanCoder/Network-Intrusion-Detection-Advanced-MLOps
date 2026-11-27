"""Runtime configuration for the real-time NDR platform.

Every value can be overridden with an environment variable so the same code
runs in local development, CI and a container deployment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_path(name: str, default: Path) -> Path:
    value = os.getenv(name)
    path = Path(value).expanduser() if value else default
    return path if path.is_absolute() else (PROJECT_ROOT / path)


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings."""

    zeek_log_dir: Path
    db_path: Path
    model_path: Path
    sensor_id: str
    sensor_mode: str
    poll_interval_s: float
    ingest_enabled: bool
    cors_origins: tuple[str, ...]
    retention_days: int
    frontend_dist: Path
    metrics_window_s: int
    ws_metrics_interval_s: float
    max_events_returned: int
    max_ws_clients: int
    ws_queue_size: int
    api_host: str
    api_port: int
    api_key: str | None = None
    remote_ingest_max_batch: int = 500

    @classmethod
    def from_env(cls) -> "Settings":
        origins = tuple(
            origin.strip()
            for origin in os.getenv(
                "NDR_CORS_ORIGINS",
                "http://localhost:5173,http://127.0.0.1:5173",
            ).split(",")
            if origin.strip()
        )
        return cls(
            zeek_log_dir=_env_path("NDR_ZEEK_LOG_DIR", PROJECT_ROOT / "data" / "zeek_logs"),
            db_path=_env_path("NDR_DB_PATH", PROJECT_ROOT / "data" / "realtime" / "ndr.db"),
            model_path=_env_path("NDR_MODEL_PATH", PROJECT_ROOT / "models" / "zeek" / "zeek_model.joblib"),
            sensor_id=os.getenv("NDR_SENSOR_ID", "zeek-sensor-01"),
            sensor_mode=os.getenv("NDR_SENSOR_MODE", "live"),
            poll_interval_s=_env_float("NDR_POLL_INTERVAL", 0.5),
            ingest_enabled=_env_bool("NDR_INGEST_ENABLED", True),
            cors_origins=origins,
            retention_days=_env_int("NDR_RETENTION_DAYS", 7),
            frontend_dist=_env_path("NDR_FRONTEND_DIST", PROJECT_ROOT / "frontend" / "dist"),
            metrics_window_s=_env_int("NDR_METRICS_WINDOW", 300),
            ws_metrics_interval_s=_env_float("NDR_WS_METRICS_INTERVAL", 1.0),
            max_events_returned=_env_int("NDR_MAX_EVENTS", 500),
            max_ws_clients=_env_int("NDR_MAX_WS_CLIENTS", 200),
            ws_queue_size=_env_int("NDR_WS_QUEUE_SIZE", 500),
            api_host=os.getenv("NDR_API_HOST", "0.0.0.0"),
            # Render (and most PaaS) inject PORT; NDR_API_PORT keeps local runs explicit.
            api_port=_env_int("PORT", _env_int("NDR_API_PORT", 8000)),
            api_key=os.getenv("NDR_API_KEY") or None,
            remote_ingest_max_batch=_env_int("NDR_INGEST_MAX_BATCH", 500),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings; tests call ``get_settings.cache_clear()``."""

    return Settings.from_env()
