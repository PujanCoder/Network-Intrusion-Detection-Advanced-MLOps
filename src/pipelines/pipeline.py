import dagshub
import mlflow


dagshub.init(
    repo_owner="pujanpandey012",
    repo_name="Network-Intrusion-Detection-Advanced-MLOps",
    mlflow=True
)

mlflow.set_experiment("Network-Intrusion-Detection")

