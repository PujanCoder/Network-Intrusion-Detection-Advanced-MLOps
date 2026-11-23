import pandas as pd
import numpy as np
import yaml
import joblib
import json

import mlflow
import mlflow.sklearn
import dagshub

from pathlib import Path

from sklearn.model_selection import train_test_split

from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

ROOT_DIR = Path(__file__).resolve().parents[2]

os_params = ROOT_DIR / "params.yaml"

with open(os_params, "r") as file:
    params = yaml.safe_load(file)


# ==========================================
# DATA PATHS
# ==========================================

X_TRAIN_PATH = ROOT_DIR / params["data"]["X_train"]
X_TEST_PATH = ROOT_DIR / params["data"]["X_test"]

Y_TRAIN_PATH = ROOT_DIR / params["data"]["y_train"]
Y_TEST_PATH = ROOT_DIR / params["data"]["y_test"]

MODEL_DIR = ROOT_DIR / "models"
REPORT_DIR = ROOT_DIR / "reports"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ==========================================
# LOAD DATA
# ==========================================

def load_data():

    print("\nLOADING TRANSFORMED DATA")
    print("=" * 50)

    X_train = pd.read_csv(X_TRAIN_PATH)
    X_test = pd.read_csv(X_TEST_PATH)

    y_train = pd.read_csv(Y_TRAIN_PATH).squeeze("columns")
    y_test = pd.read_csv(Y_TEST_PATH).squeeze("columns")

    print("X_train:", X_train.shape)
    print("X_test:", X_test.shape)

    print("y_train:", y_train.shape)
    print("y_test:", y_test.shape)

    if X_train.isna().any().any() or X_test.isna().any().any():
        raise ValueError("Missing values detected in features.")

    if not np.isfinite(X_train.to_numpy()).all():
        raise ValueError("Non-finite values detected in training data.")

    if not np.isfinite(X_test.to_numpy()).all():
        raise ValueError("Non-finite values detected in testing data.")

    if len(X_train) != len(y_train):
        raise ValueError("Training features and labels have different lengths.")

    if len(X_test) != len(y_test):
        raise ValueError("Testing features and labels have different lengths.")

    return X_train, X_test, y_train, y_test


# ==========================================
# INITIALIZE MODELS
# ==========================================

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
        )

    }

    return models


# ==========================================
# MODEL EVALUATION
# ==========================================

def evaluate_model(model, X, y):

    predictions = model.predict(X)

    metrics = {

        "accuracy": float(
            accuracy_score(y, predictions)
        ),

        "precision_macro": float(
            precision_score(
                y,
                predictions,
                average="macro",
                zero_division=0
            )
        ),

        "recall_macro": float(
            recall_score(
                y,
                predictions,
                average="macro",
                zero_division=0
            )
        ),

        "f1_macro": float(
            f1_score(
                y,
                predictions,
                average="macro",
                zero_division=0
            )
        ),

        "f1_weighted": float(
            f1_score(
                y,
                predictions,
                average="weighted",
                zero_division=0
            )
        )

    }

    return metrics, predictions


# ==========================================
# MODEL TRAINING
# ==========================================

def train_models(X_train, X_test, y_train, y_test):

    models = initialize_models()

    results = {}

    # Split training data into training and validation.
    X_subtrain, X_val, y_subtrain, y_val = train_test_split(

        X_train,
        y_train,

        test_size=params["model"]["test_size"],

        random_state=params["model"]["random_state"],

        stratify=y_train

    )

    # DagsHub MLflow initialization
    dagshub.init(
        repo_owner="pujanpandey012",
        repo_name="Network-Intrusion-Detection-Advanced-MLOps",
        mlflow=True
    )

    mlflow.set_experiment(
        params["mlflow"]["experiment_name"]
    )

    best_model = None
    best_model_name = None
    best_score = -1

    print("\nSTARTING MODEL TRAINING")
    print("=" * 50)

    for model_name, model in models.items():

        with mlflow.start_run(run_name=model_name):

            print(f"\nTraining: {model_name}")

            # Training
            model.fit(X_subtrain, y_subtrain)

            # Validation
            val_metrics, _ = evaluate_model(
                model,
                X_val,
                y_val
            )

            # Log parameters
            mlflow.log_params(
                model.get_params()
            )

            mlflow.log_param(
                "model_name",
                model_name
            )

            mlflow.log_param(
                "training_samples",
                len(X_subtrain)
            )

            mlflow.log_param(
                "validation_samples",
                len(X_val)
            )

            # Log validation metrics
            mlflow.log_metrics(val_metrics)

            # Log trained model
            mlflow.sklearn.log_model(
    sk_model=model,
    name="model",

    registered_model_name=params["mlflow"]["registered_model_name"],

    skops_trusted_types=[
        "sklearn.tree._tree.Tree"
    ]
)

            results[model_name] = val_metrics

            print("Validation metrics:")

            for metric, value in val_metrics.items():
                print(f"{metric}: {value:.5f}")

            # Select model using validation F1
            if val_metrics["f1_macro"] > best_score:

                best_score = val_metrics["f1_macro"]

                best_model = model
                best_model_name = model_name

    # ======================================
    # FINAL TEST EVALUATION
    # ======================================

    print("\nBEST MODEL:", best_model_name)

    test_metrics, predictions = evaluate_model(
        best_model,
        X_test,
        y_test
    )

    print("\nFINAL TEST RESULTS")
    print("=" * 50)

    for metric, value in test_metrics.items():
        print(f"{metric}: {value:.5f}")

    print("\nCLASSIFICATION REPORT")

    report = classification_report(
        y_test,
        predictions,
        zero_division=0
    )

    print(report)

    print("\nCONFUSION MATRIX")

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(matrix)

    # ======================================
    # SAVE BEST MODEL
    # ======================================

    model_path = MODEL_DIR / "best_model.joblib"

    joblib.dump(best_model, model_path)

    # ======================================
    # SAVE METRICS
    # ======================================

    final_results = {

        "best_model": best_model_name,

        "validation_metrics": results,

        "test_metrics": test_metrics,

        "classification_report": classification_report(
            y_test,
            predictions,
            output_dict=True,
            zero_division=0
        ),

        "confusion_matrix": matrix.tolist()

    }

    metrics_path = REPORT_DIR / "model_metrics.json"

    with open(metrics_path, "w") as file:

        json.dump(
            final_results,
            file,
            indent=4
        )

    # ======================================
    # LOG FINAL MODEL TO MLFLOW
    # ======================================

    with mlflow.start_run(
        run_name="Best_Model_Final_Evaluation"
    ):

        mlflow.log_param(
            "best_model",
            best_model_name
        )

        mlflow.log_metrics(test_metrics)
        mlflow.sklearn.log_model(
    sk_model=best_model,
    name="best_model",
    registered_model_name=params["mlflow"]["registered_model_name"],
    skops_trusted_types=["sklearn.tree._tree.Tree"]
)

    print("\nMODEL TRAINING COMPLETED")

    print("Saved model:", model_path)

    print("Saved metrics:", metrics_path)


# ==========================================
# MAIN
# ==========================================

def main():

    X_train, X_test, y_train, y_test = load_data()

    train_models(
        X_train,
        X_test,
        y_train,
        y_test
    )


if __name__ == "__main__":

    main()