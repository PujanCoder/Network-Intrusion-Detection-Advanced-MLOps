import json
import logging
from pathlib import Path

import dagshub
import joblib
import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
import yaml

from sklearn.model_selection import train_test_split

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier


from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
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

X_TRAIN_PATH = ROOT_DIR / params["data"]["X_train"]
X_TEST_PATH = ROOT_DIR / params["data"]["X_test"]

Y_TRAIN_PATH = ROOT_DIR / params["data"]["y_train"]
Y_TEST_PATH = ROOT_DIR / params["data"]["y_test"]

MODEL_DIR = ROOT_DIR / "models"
REPORT_DIR = ROOT_DIR / "reports"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
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

    experiment_name = params["mlflow"]["experiment_name"]

    mlflow.set_experiment(experiment_name)

    logger.info(
        "MLflow tracking URI: %s",
        mlflow.get_tracking_uri(),
    )

    logger.info(
        "MLflow experiment: %s",
        experiment_name,
    )


# ==========================================================
# LOAD DATA
# ==========================================================

def load_data():

    logger.info("Loading transformed datasets.")

    X_train = pd.read_csv(X_TRAIN_PATH)
    X_test = pd.read_csv(X_TEST_PATH)

    y_train = pd.read_csv(Y_TRAIN_PATH).squeeze("columns")
    y_test = pd.read_csv(Y_TEST_PATH).squeeze("columns")

    if X_train.isna().any().any() or X_test.isna().any().any():
        raise ValueError("Missing values detected in features.")

    if not np.isfinite(X_train.to_numpy()).all():
        raise ValueError("Non-finite values in training features.")

    if not np.isfinite(X_test.to_numpy()).all():
        raise ValueError("Non-finite values in testing features.")

    if len(X_train) != len(y_train):
        raise ValueError("Training feature-label mismatch.")

    if len(X_test) != len(y_test):
        raise ValueError("Testing feature-label mismatch.")

    if list(X_train.columns) != list(X_test.columns):
        raise ValueError("Training and testing feature columns do not match.")

    logger.info("Training dataset: %s", X_train.shape)
    logger.info("Testing dataset: %s", X_test.shape)

    return X_train, X_test, y_train, y_test


# ==========================================================
# INITIALIZE MODELS
# ==========================================================

def initialize_models():

    config = params["model"]["algorithms"]

    models = {

        "Logistic Regression": LogisticRegression(
            **config["logistic_regression"]
        ),

        "Decision Tree": DecisionTreeClassifier(
            **config["decision_tree"]
        ),

        "Random Forest": RandomForestClassifier(
            **config["random_forest"]
        ),

    }

    return models


# ==========================================================
# VALIDATION METRICS
# ==========================================================

def calculate_metrics(model, X, y):

    predictions = model.predict(X)

    metrics = {

        "accuracy": accuracy_score(
            y,
            predictions,
        ),

        "precision_macro": precision_score(
            y,
            predictions,
            average="macro",
            zero_division=0,
        ),

        "recall_macro": recall_score(
            y,
            predictions,
            average="macro",
            zero_division=0,
        ),

        "f1_macro": f1_score(
            y,
            predictions,
            average="macro",
            zero_division=0,
        ),

        "f1_weighted": f1_score(
            y,
            predictions,
            average="weighted",
            zero_division=0,
        ),

        "ddos_precision": precision_score(
            y,
            predictions,
            pos_label="DDoS",
            average="binary",
            zero_division=0,
        ),

        "ddos_recall": recall_score(
            y,
            predictions,
            pos_label="DDoS",
            average="binary",
            zero_division=0,
        ),

        "ddos_f1": f1_score(
            y,
            predictions,
            pos_label="DDoS",
            average="binary",
            zero_division=0,
        ),

    }

    return metrics


# ==========================================================
# MODEL TRAINING
# ==========================================================

def train_models(X_train, X_test, y_train, y_test):

    logger.info("Initializing MLflow.")

    initialize_mlflow()

    models = initialize_models()

    test_size = params["model"]["test_size"]
    random_state = params["model"]["random_state"]

    # ------------------------------------------------------
    # TRAIN / VALIDATION SPLIT
    # ------------------------------------------------------

    X_subtrain, X_val, y_subtrain, y_val = train_test_split(

        X_train,
        y_train,

        test_size=test_size,

        random_state=random_state,

        stratify=y_train,

    )

    logger.info("Training subset: %s", X_subtrain.shape)
    logger.info("Validation subset: %s", X_val.shape)

    results = {}

    best_model_name = None
    best_model = None
    best_score = -1

    # ------------------------------------------------------
    # TRAIN CANDIDATE MODELS
    # ------------------------------------------------------

    logger.info("Starting candidate model training.")

    for model_name, model in models.items():

        logger.info("Training %s", model_name)

        with mlflow.start_run(run_name=model_name):

            # Train
            model.fit(
                X_subtrain,
                y_subtrain,
            )

            # Validate
            validation_metrics = calculate_metrics(
                model,
                X_val,
                y_val,
            )

            # Store validation metrics
            results[model_name] = {
                key: float(value)
                for key, value in validation_metrics.items()
            }

            # MLflow tags
            mlflow.set_tag("model_role", "candidate")
            mlflow.set_tag("model_name", model_name)

            # Log parameters
            mlflow.log_params(model.get_params())

            mlflow.log_param(
                "training_samples",
                len(X_subtrain),
            )

            mlflow.log_param(
                "validation_samples",
                len(X_val),
            )

            mlflow.log_param(
                "validation_test_size",
                test_size,
            )

            mlflow.log_param(
                "validation_random_state",
                random_state,
            )

            # Log validation metrics
            mlflow.log_metrics(
                {
                    key: float(value)
                    for key, value in validation_metrics.items()
                }
            )

            # Log model to MLflow
            model_info = mlflow.sklearn.log_model(
                sk_model=model,
                name="model",
                skops_trusted_types=[
                    "sklearn.tree._tree.Tree"
                ],
            )

            # Save logged model URI in run metadata
            mlflow.set_tag(
                "model_uri",
                model_info.model_uri,
            )

            logger.info(
                "%s logged successfully: %s",
                model_name,
                model_info.model_uri,
            )

            logger.info(
                "%s validation F1: %.5f",
                model_name,
                validation_metrics["f1_macro"],
            )

            # Select best candidate
            if validation_metrics["f1_macro"] > best_score:

                best_score = validation_metrics["f1_macro"]

                best_model_name = model_name

                best_model = model

    if best_model is None:
        raise RuntimeError("No candidate model was successfully trained.")

    # ------------------------------------------------------
    # SAVE BEST VALIDATION MODEL
    # ------------------------------------------------------

    model_path = MODEL_DIR / "best_model.joblib"

    joblib.dump(
        best_model,
        model_path,
    )

    # ------------------------------------------------------
    # SAVE VALIDATION RESULTS
    # ------------------------------------------------------

    training_results = {

        "best_model": best_model_name,

        "best_validation_f1": float(best_score),

        "validation_metrics": results,

    }

    metrics_path = REPORT_DIR / "training_results.json"

    with open(
        metrics_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            training_results,
            file,
            indent=4,
        )

    logger.info("Candidate model training completed.")

    logger.info("Best candidate: %s", best_model_name)

    logger.info("Saved model: %s", model_path)

    logger.info("Saved results: %s", metrics_path)

    return training_results


# ==========================================================
# MAIN
# ==========================================================

def main():

    X_train, X_test, y_train, y_test = load_data()

    train_models(
        X_train,
        X_test,
        y_train,
        y_test,
    )

if __name__ == "__main__":

    main()