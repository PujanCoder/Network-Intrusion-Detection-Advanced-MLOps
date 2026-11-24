import json
import logging
from pathlib import Path

import dagshub
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
import yaml

from sklearn.model_selection import train_test_split

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    classification_report,
    confusion_matrix,
)


# ==========================================================
# LOGGING
# ==========================================================

logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)


# ==========================================================
# PROJECT CONFIGURATION
# ==========================================================

ROOT_DIR = Path(__file__).resolve().parents[2]

PARAMS_PATH = ROOT_DIR / "params.yaml"

with open(PARAMS_PATH, "r", encoding="utf-8") as file:
    params = yaml.safe_load(file)


# ==========================================================
# DATA PATHS
# ==========================================================

DATA_DIR = ROOT_DIR / "data" / "processed" / "transformed"

REPORT_DIR = ROOT_DIR / "reports" / "model_evaluation"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================================
# DAGSHUB / MLFLOW CONFIGURATION
# ==========================================================

def initialize_mlflow():

    dagshub.init(
        repo_owner="pujanpandey012",
        repo_name="Network-Intrusion-Detection-Advanced-MLOps",
        mlflow=True,
    )

    logger.info(
        "MLflow tracking URI: %s",
        mlflow.get_tracking_uri(),
    )


# ==========================================================
# LOAD EVALUATION DATA
# ==========================================================

def load_evaluation_data():

    logger.info("Loading evaluation datasets.")

    X_train = pd.read_csv(
        DATA_DIR / "X_train_selected.csv"
    )

    X_test = pd.read_csv(
        DATA_DIR / "X_test_selected.csv"
    )

    y_train = pd.read_csv(
        DATA_DIR / "y_train.csv"
    ).squeeze("columns")

    y_test = pd.read_csv(
        DATA_DIR / "y_test.csv"
    ).squeeze("columns")

    if list(X_train.columns) != list(X_test.columns):
        raise ValueError(
            "Training and testing feature columns do not match."
        )

    if len(X_train) != len(y_train):
        raise ValueError("Training feature-label mismatch.")

    if len(X_test) != len(y_test):
        raise ValueError("Testing feature-label mismatch.")

    # Reproduce the same validation split used during training.
    test_size = params["model"]["test_size"]

    random_state = params["model"]["random_state"]

    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train,
        y_train,
        test_size=test_size,
        random_state=random_state,
        stratify=y_train,
    )

    logger.info("Validation dataset: %s", X_val.shape)

    logger.info("Testing dataset: %s", X_test.shape)

    return X_val, y_val, X_test, y_test


# ==========================================================
# CALCULATE METRICS
# ==========================================================

def calculate_metrics(model, X, y):

    predictions = model.predict(X)

    metrics = {

        "accuracy": float(
            accuracy_score(y, predictions)
        ),

        "precision": float(
            precision_score(
                y,
                predictions,
                average="binary",
                pos_label="DDoS",
                zero_division=0,
            )
        ),

        "recall": float(
            recall_score(
                y,
                predictions,
                average="binary",
                pos_label="DDoS",
                zero_division=0,
            )
        ),

        "f1_score": float(
            f1_score(
                y,
                predictions,
                average="binary",
                pos_label="DDoS",
                zero_division=0,
            )
        ),

    }

    # ROC-AUC
    if hasattr(model, "predict_proba"):

        probabilities = model.predict_proba(X)

        classes = list(model.classes_)

        if "DDoS" in classes:

            ddos_index = classes.index("DDoS")

            metrics["roc_auc"] = float(
                roc_auc_score(
                    (y == "DDoS").astype(int),
                    probabilities[:, ddos_index],
                )
            )

        else:

            metrics["roc_auc"] = None

    else:

        metrics["roc_auc"] = None

    return metrics


# ==========================================================
# GET COMPLETED CANDIDATE MODEL RUNS
# ==========================================================

def get_completed_model_runs(experiment_name):

    initialize_mlflow()

    experiment = mlflow.get_experiment_by_name(
        experiment_name
    )

    if experiment is None:

        raise ValueError(
            f"MLflow experiment '{experiment_name}' not found."
        )

    runs = mlflow.search_runs(

        experiment_ids=[
            experiment.experiment_id
        ],

        filter_string=(
            "attributes.status = 'FINISHED' "
            "and tags.model_role = 'candidate'"
        ),

        order_by=[
            "start_time DESC"
        ],

    )

    if runs.empty:

        raise ValueError(
            "No completed candidate model runs found. "
            "Run model training first."
        )

    logger.info(
        "Found %d candidate runs.",
        len(runs),
    )

    return runs


# ==========================================================
# MODEL EVALUATION
# ==========================================================

def evaluate_models(
    experiment_name="Network-Intrusion-Detection",
):

    logger.info("Starting model evaluation.")

    # Load validation and test datasets
    X_val, y_val, X_test, y_test = load_evaluation_data()

    # Get candidate runs
    runs = get_completed_model_runs(
        experiment_name
    )

    results = []

    evaluated_models = {}

    # ------------------------------------------------------
    # EVALUATE CANDIDATE MODELS ON VALIDATION DATA
    # ------------------------------------------------------

    for _, run in runs.iterrows():

        run_id = run["run_id"]

        # Correct Pandas Series access
        model_uri = run.get("tags.model_uri")

        if pd.isna(model_uri) or not model_uri:

            logger.warning(
                "No logged model URI found for run %s",
                run_id,
            )

            continue

        try:

            logger.info(
                "Loading model from run: %s",
                run_id,
            )

            # Load logged MLflow model
            model = mlflow.sklearn.load_model(
                model_uri
            )

            validation_metrics = calculate_metrics(
                model,
                X_val,
                y_val,
            )

            results.append({

                "run_id": run_id,

                "model_uri": model_uri,

                **validation_metrics,

            })

            evaluated_models[run_id] = model

            logger.info(
                "Run %s | Validation F1: %.5f",
                run_id,
                validation_metrics["f1_score"],
            )

        except Exception as error:

            logger.exception(
                "Could not evaluate run %s: %s",
                run_id,
                error,
            )

    if not results:

        raise RuntimeError(
            "No compatible candidate models could be evaluated."
        )

    # ------------------------------------------------------
    # MODEL COMPARISON
    # ------------------------------------------------------

    results_df = pd.DataFrame(results)

    results_df = results_df.sort_values(
        by="f1_score",
        ascending=False,
    ).reset_index(drop=True)

    comparison_path = REPORT_DIR / "model_comparison.csv"

    results_df.to_csv(
        comparison_path,
        index=False,
    )

    # ------------------------------------------------------
    # SELECT BEST MODEL
    # ------------------------------------------------------

    best_result = results_df.iloc[0]

    best_run_id = best_result["run_id"]

    best_model = evaluated_models[best_run_id]

    logger.info(
        "Best model selected: %s",
        best_run_id,
    )

    logger.info(
        "Best validation F1: %.5f",
        best_result["f1_score"],
    )

    # ------------------------------------------------------
    # FINAL TEST EVALUATION
    # ------------------------------------------------------

    logger.info(
        "Evaluating selected model on untouched test data."
    )

    test_metrics = calculate_metrics(
        best_model,
        X_test,
        y_test,
    )

    test_predictions = best_model.predict(
        X_test
    )

    report = classification_report(
        y_test,
        test_predictions,
        zero_division=0,
        output_dict=True,
    )

    confusion = confusion_matrix(
        y_test,
        test_predictions,
        labels=["BENIGN", "DDoS"],
    )

    # ------------------------------------------------------
    # SAVE RESULTS
    # ------------------------------------------------------

    evaluation_results = {

        "best_run_id": best_run_id,

        "model_uri": best_result["model_uri"],

        "validation_metrics": {

            key: (
                None if pd.isna(best_result[key])
                else float(best_result[key])
            )

            for key in [
                "accuracy",
                "precision",
                "recall",
                "f1_score",
                "roc_auc",
            ]

        },

        "test_metrics": test_metrics,

        "classification_report": report,

        "confusion_matrix": confusion.tolist(),

    }

    results_path = REPORT_DIR / "evaluation_results.json"

    with open(
        results_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            evaluation_results,
            file,
            indent=4,
        )

    logger.info(
        "Model comparison saved: %s",
        comparison_path,
    )

    logger.info(
        "Evaluation results saved: %s",
        results_path,
    )

    logger.info("Model evaluation completed successfully.")

    return evaluation_results


# ==========================================================
# MAIN
# ==========================================================

if __name__ == "__main__":

    evaluate_models()