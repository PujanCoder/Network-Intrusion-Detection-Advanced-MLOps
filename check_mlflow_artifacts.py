import mlflow
from mlflow.tracking import MlflowClient

EXPERIMENT_NAME = "Network-Intrusion-Detection"

client = MlflowClient()

experiment = client.get_experiment_by_name(EXPERIMENT_NAME)

if experiment is None:
    raise ValueError("MLflow experiment not found.")

runs = client.search_runs(
    experiment_ids=[experiment.experiment_id],
    max_results=20,
    order_by=["start_time DESC"],
)

for run in runs:
    print("\n" + "=" * 60)
    print("Run ID:", run.info.run_id)
    print("Status:", run.info.status)

    try:
        artifacts = client.list_artifacts(run.info.run_id)

        for artifact in artifacts:
            print("Artifact:", artifact.path)

    except Exception as error:
        print("Artifact error:", error)