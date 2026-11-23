import logging
import mlflow
from mlflow.tracking import MlflowClient

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MLflow configuration
EXPERIMENT_NAME = "Network-Intrusion-Detection"
REGISTERED_MODEL_NAME = "Network-Intrusion-Detection-Model"


def register_model(run_id: str):
    """
    Register the selected model from an MLflow run.

    Args:
        run_id: MLflow run ID of the best model.

    Returns:
        Model version information.
    """

    if not run_id:
        raise ValueError("A valid MLflow run ID is required.")

    client = MlflowClient()

    model_uri = f"runs:/{run_id}/model"

    logger.info("Registering model from run: %s", run_id)

    # Register model in MLflow Model Registry
    model_version = mlflow.register_model(
        model_uri=model_uri,
        name=REGISTERED_MODEL_NAME,
    )

    logger.info(
        "Model registered successfully. Name: %s, Version: %s",
        model_version.name,
        model_version.version,
    )

    # Add metadata
    client.set_model_version_tag(
        name=REGISTERED_MODEL_NAME,
        version=model_version.version,
        key="source_run_id",
        value=run_id,
    )

    client.set_model_version_tag(
        name=REGISTERED_MODEL_NAME,
        version=model_version.version,
        key="project",
        value="Network-Intrusion-Detection-Advanced-MLOps",
    )

    logger.info("Model registration completed.")

    return model_version


if __name__ == "__main__":
    print("Run model registration through pipeline.py.")