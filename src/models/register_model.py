import mlflow
from mlflow.tracking import MlflowClient
from pathlib import Path

from src.utils.common import load_config


def register_model():

    config = load_config()

    mlflow.set_tracking_uri(config["mlflow"]["tracking_uri"])

    client = MlflowClient()

    experiment_name = config["mlflow"]["experiment_name"]

    experiment = client.get_experiment_by_name(experiment_name)

    if experiment is None:
        raise ValueError("MLflow experiment not found")

    runs = client.search_runs(
        experiment_ids=[experiment.experiment_id],
        order_by=["start_time DESC"],
        max_results=10
    )

    if not runs:
        raise ValueError("No MLflow runs found")

    best_run = max(
        runs,
        key=lambda run: run.data.metrics.get("f1_score", 0)
    )

    run_id = best_run.info.run_id

    model_uri = f"runs:/{run_id}/model"

    registered_name = "Network-Intrusion-Detection"

    result = mlflow.register_model(
        model_uri=model_uri,
        name=registered_name
    )

    print("\nMODEL REGISTRATION SUCCESSFUL")
    print("=" * 40)
    print(f"Model Name: {registered_name}")
    print(f"Model Version: {result.version}")
    print(f"Run ID: {run_id}")


if __name__ == "__main__":
    register_model()