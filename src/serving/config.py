import os
from pathlib import Path

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDS_", extra="ignore")

    # The platform secret is called NDR_API_KEY; this app historically used
    # IDS_API_KEY. Accepting both lets one Render secret configure both apps.
    api_key: str = Field(default="", validation_alias=AliasChoices("IDS_API_KEY", "NDR_API_KEY"))
    model_path: Path = Path("models/cic_ids2017_xgb.joblib")
    feature_order_path: Path = Path("models/feature_order.json")
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
