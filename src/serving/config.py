from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IDS_", extra="ignore")

    api_key: str = "change-me"
    model_path: Path = Path("models/cic_ids2017_xgb.joblib")
    feature_order_path: Path = Path("models/feature_order.json")
    db_path: Path = Path("data/ids.db")

    # Zeek ingestion (Phase 2+)
    zeek_enabled: bool = False
    zeek_log_dir: Path = Path("data/interim/zeek/current")
    zeek_poll_interval: float = 1.0
    zeek_sensor_id: str = "local-sensor"
    zeek_log_types: str = "conn,dns,http,ssl,files,notice"
    zeek_retention_days: int = 14
    zeek_pcap_dir: Path = Path("data/raw/pcap")
    zeek_run_dir: Path = Path("data/interim/zeek/runs")
    zeek_bin: str = "zeek"
