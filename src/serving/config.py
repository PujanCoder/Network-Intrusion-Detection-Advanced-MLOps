import os
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDS_", extra="ignore")

    # The platform secret is called NDR_API_KEY; this app historically used
    # IDS_API_KEY. Accepting both lets one Render secret configure both apps.
    api_key: str = Field(default="", validation_alias=AliasChoices("IDS_API_KEY", "NDR_API_KEY"))
    # Declared for operators who set IDS_MODEL_PATH; src.serving.predictor owns the
    # actual resolution (repository-root relative, env overridable).
    model_path: Path = Path("models/best_model.joblib")
    preprocessor_path: Path = Path("models/preprocessor.joblib")
    db_path: Path = Path("data/ids.db")

    # Zeek ingestion (Phase 2+)
    zeek_enabled: bool = False
    zeek_model_path: Path = Path("models/zeek/zeek_model.joblib")
    zeek_log_dir: Path = Path("data/interim/zeek/current")
    zeek_poll_interval: float = 1.0
    zeek_sensor_id: str = "local-sensor"
    zeek_log_types: str = "conn,dns,http,ssl,files,notice"
    zeek_retention_days: int = 14
    zeek_pcap_dir: Path = Path("data/raw/pcap")
    zeek_run_dir: Path = Path("data/interim/zeek/runs")
    zeek_bin: str = "zeek"

    # Dashboard session. The token is derived from the API key unless an explicit
    # secret is set; it never leaves the server except as an HttpOnly cookie.
    session_secret: str = Field(default="", validation_alias=AliasChoices("IDS_SESSION_SECRET", "NDR_SESSION_SECRET"))
    session_ttl_s: int = 8 * 3600
    # Secure cookies require HTTPS. Unset means "decide per request" (https or
    # X-Forwarded-Proto: https), which is right for Render and for local uvicorn.
    session_cookie_secure: bool | None = Field(
        default=None, validation_alias=AliasChoices("IDS_SESSION_COOKIE_SECURE", "NDR_SESSION_COOKIE_SECURE")
    )
    session_samesite: str = "lax"

    # React dashboard bundle. Built into the repository checkout so the hosting
    # build command stays unchanged; NDR_FRONTEND_DIST can point elsewhere.
    frontend_dist: Path = Field(
        default=Path("frontend/dist"), validation_alias=AliasChoices("IDS_FRONTEND_DIST", "NDR_FRONTEND_DIST")
    )

    # Dashboard data windows and liveness thresholds.
    metrics_window_s: int = 3600
    rate_window_s: int = 300
    sensor_stale_after_s: int = 300
    max_ws_clients: int = 64

    @property
    def api_key_source(self) -> str | None:
        """Environment variable that supplied the API key, if any."""

        for name in ("IDS_API_KEY", "NDR_API_KEY"):
            if os.getenv(name):
                return name
        return None

    @property
    def auth_configured(self) -> bool:
        return bool(self.api_key.strip())
