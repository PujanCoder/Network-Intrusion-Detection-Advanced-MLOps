"""MLflow tracking configuration shared by the batch training stages.

DagsHub is used when a token is available. Without credentials the run falls
back to the local SQLite store that ships with the repository, so the DVC
pipeline stays reproducible offline and on a clean CI runner.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import mlflow

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parents[2]

DAGSHUB_REPO_OWNER = "pujanpandey012"
DAGSHUB_REPO_NAME = "Network-Intrusion-Detection-Advanced-MLOps"


def configure_tracking() -> str:
    """Point MLflow at an available backend and return the tracking URI."""

    explicit = os.getenv("MLFLOW_TRACKING_URI")
    if explicit:
        mlflow.set_tracking_uri(explicit)
        logger.info("MLflow tracking URI (environment): %s", explicit)
        return explicit

    token = os.getenv("DAGSHUB_USER_TOKEN") or os.getenv("DAGSHUB_TOKEN")
    if token:
        import dagshub

        dagshub.init(
            repo_owner=DAGSHUB_REPO_OWNER,
            repo_name=DAGSHUB_REPO_NAME,
            mlflow=True,
        )
        uri = mlflow.get_tracking_uri()
        logger.info("MLflow tracking URI (DagsHub): %s", uri)
        return uri

    local_uri = f"sqlite:///{(ROOT_DIR / 'mlflow.db').as_posix()}"
    mlflow.set_tracking_uri(local_uri)
    logger.warning(
        "No DAGSHUB_USER_TOKEN or MLFLOW_TRACKING_URI set; using local MLflow store %s",
        local_uri,
    )
    return local_uri
