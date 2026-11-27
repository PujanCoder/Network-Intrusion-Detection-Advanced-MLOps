from pathlib import Path
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    api_key: str = "change-me"
    model_path: Path = Path("models/cic_ids2017_xgb.joblib")
    feature_order_path: Path = Path("models/feature_order.json")
    db_path: Path = Path("data/ids.db")

    class Config:
        env_prefix = "IDS_"