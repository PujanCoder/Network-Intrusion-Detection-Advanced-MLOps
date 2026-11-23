
import logging
import pandas as pd

from pathlib import Path

from src.features.data_cleaning import (
    clean_data,
    handle_outliers_iqr,
)

from src.features.data_preprocessing import (
    split_data,
    validate_data_drift,
)

from src.features.feature_transformation import (
    transform_features,
)

from src.features.transformation_validation import (
    remove_constant_features,
)

from src.models.train_model import train_models
from src.models.evaluate_model import evaluate_models
from src.models.register_model import register_model


# ============================================================
# LOGGING CONFIGURATION
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

logger = logging.getLogger(__name__)


# ============================================================
# PATH CONFIGURATION
# ============================================================

ROOT_DIR = Path(__file__).resolve().parents[2]

RAW_DATA_PATH = (
    ROOT_DIR
    / "data"
    / "raw"
    / "MachineLearningCSV"
    / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

PROCESSED_DIR = ROOT_DIR / "data" / "processed"

TRANSFORMED_DIR = PROCESSED_DIR / "transformed"

REPORT_DIR = ROOT_DIR / "reports"


# ============================================================
# DATA VALIDATION
# ============================================================

def validate_input_data(df: pd.DataFrame) -> None:
    """Validate the cleaned dataset."""

    if df.empty:
        raise ValueError("Input dataset is empty.")

    if "Label" not in df.columns:
        raise ValueError("Target column 'Label' not found.")

    if df["Label"].nunique() < 2:
        raise ValueError(
            "Dataset must contain at least two classes."
        )

    if df.isnull().sum().sum() > 0:
        raise ValueError(
            "Dataset contains missing values."
        )

    if not np.isfinite(
        df.select_dtypes(include="number").to_numpy()
    ).all():
        raise ValueError(
            "Dataset contains infinite numerical values."
        )

    logger.info("Input data validation passed.")


# ============================================================
# PROCESSED DATA VALIDATION
# ============================================================

def validate_processed_data(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series,
) -> None:
    """Validate final datasets before model training."""

    if X_train.empty or X_test.empty:
        raise ValueError("Training or testing dataset is empty.")

    if len(X_train) != len(y_train):
        raise ValueError("Training feature-label mismatch.")

    if len(X_test) != len(y_test):
        raise ValueError("Testing feature-label mismatch.")

    if list(X_train.columns) != list(X_test.columns):
        raise ValueError(
            "Training and testing feature columns do not match."
        )

    for name, data in {
        "X_train": X_train,
        "X_test": X_test,
    }.items():

        if data.isnull().sum().sum() > 0:
            raise ValueError(
                f"{name} contains missing values."
            )

        if not np.isfinite(data.to_numpy()).all():
            raise ValueError(
                f"{name} contains infinite values."
            )

    logger.info("Processed dataset validation passed.")


# ============================================================
# MAIN PIPELINE
# ============================================================

def run_pipeline():

    logger.info("=" * 65)
    logger.info("NETWORK INTRUSION DETECTION - COMPLETE MLOPS PIPELINE")
    logger.info("=" * 65)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------
    # STEP 1: DATA INGESTION
    # --------------------------------------------------------

    logger.info("[1/10] DATA INGESTION")

    if not RAW_DATA_PATH.exists():
        raise FileNotFoundError(
            f"Raw dataset not found: {RAW_DATA_PATH}"
        )

    df = pd.read_csv(RAW_DATA_PATH)

    df.columns = (
        df.columns
        .str.replace("\ufeff", "", regex=False)
        .str.strip()
    )

    logger.info("Raw dataset shape: %s", df.shape)

    # --------------------------------------------------------
    # STEP 2: DATA CLEANING
    # --------------------------------------------------------

    logger.info("[2/10] DATA CLEANING")

    df = clean_data(df)

    validate_input_data(df)

    logger.info("Cleaned dataset shape: %s", df.shape)

    # --------------------------------------------------------
    # STEP 3: DATA SPLITTING
    # --------------------------------------------------------

    logger.info("[3/10] DATA SPLITTING")

    X_train, X_test, y_train, y_test = split_data(
        df,
        target_column="Label",
        test_size=0.20,
        random_state=42,
    )

    logger.info("Training features: %s", X_train.shape)
    logger.info("Testing features: %s", X_test.shape)

    # --------------------------------------------------------
    # STEP 4: OUTLIER HANDLING
    # --------------------------------------------------------

    logger.info("[4/10] OUTLIER HANDLING")

    train_df = X_train.copy()
    train_df["Label"] = y_train

    processed_train, outlier_report = handle_outliers_iqr(
        train_df
    )

    X_train = processed_train.drop(columns=["Label"])
    y_train = processed_train["Label"]

    X_test = X_test.copy()

    for _, row in outlier_report.iterrows():

        feature = row["Feature"]

        if feature in X_test.columns:
            X_test[feature] = X_test[feature].clip(
                lower=row["Lower Bound"],
                upper=row["Upper Bound"],
            )

    outlier_report.to_csv(
        REPORT_DIR / "outlier_report.csv",
        index=False,
    )

    logger.info("Outlier handling completed.")

    # --------------------------------------------------------
    # STEP 5: DATA DRIFT VALIDATION
    # --------------------------------------------------------

    logger.info("[5/10] DATA DRIFT VALIDATION")

    snapshot = validate_data_drift(
        reference_data=X_train,
        current_data=X_test,
    )

    drift_report_path = REPORT_DIR / "data_drift_report.html"

    snapshot.save_html(str(drift_report_path))

    logger.info(
        "Data drift report saved: %s",
        drift_report_path,
    )

    # --------------------------------------------------------
    # STEP 6: FEATURE TRANSFORMATION
    # --------------------------------------------------------

    logger.info("[6/10] FEATURE TRANSFORMATION")

    transform_features(
        X_train,
        X_test,
        y_train,
        y_test,
    )

    # --------------------------------------------------------
    # STEP 7: TRANSFORMATION VALIDATION
    # --------------------------------------------------------

    logger.info("[7/10] TRANSFORMATION VALIDATION")

    remove_constant_features()

    X_train_final = pd.read_csv(
        TRANSFORMED_DIR / "X_train_selected.csv"
    )

    X_test_final = pd.read_csv(
        TRANSFORMED_DIR / "X_test_selected.csv"
    )

    y_train_final = pd.read_csv(
        TRANSFORMED_DIR / "y_train.csv"
    ).squeeze("columns")

    y_test_final = pd.read_csv(
        TRANSFORMED_DIR / "y_test.csv"
    ).squeeze("columns")

    validate_processed_data(
        X_train_final,
        X_test_final,
        y_train_final,
        y_test_final,
    )

    logger.info(
        "Final training dataset: %s",
        X_train_final.shape,
    )

    logger.info(
        "Final testing dataset: %s",
        X_test_final.shape,
    )

        # ==========================================================
    # 8. MODEL TRAINING
    # ==========================================================

    logger.info("[8/10] MODEL TRAINING")

    DATA_DIR = (
        Path(__file__).resolve().parents[2]
        / "data"
        / "processed"
        / "transformed"
    )

    # Load selected training and testing datasets
    X_train = pd.read_csv(DATA_DIR / "X_train_selected.csv")
    X_test = pd.read_csv(DATA_DIR / "X_test_selected.csv")

    y_train = pd.read_csv(DATA_DIR / "y_train.csv").squeeze("columns")
    y_test = pd.read_csv(DATA_DIR / "y_test.csv").squeeze("columns")

    logger.info("Training features: %s", X_train.shape)
    logger.info("Testing features: %s", X_test.shape)

    # Train candidate models
    train_results = train_models(
        X_train,
        X_test,
        y_train,
        y_test
    )

    logger.info("Model training completed successfully.")

    # --------------------------------------------------------
    # STEP 9: MODEL EVALUATION
    # --------------------------------------------------------

    logger.info("[9/10] MODEL EVALUATION")

    evaluation_results = evaluate_models()

    if not evaluation_results:
        raise RuntimeError(
            "Model evaluation returned no results."
        )

    best_run_id = evaluation_results.get("best_run_id")

    if not best_run_id:
        raise RuntimeError(
            "No best model run ID returned from evaluation."
        )

    logger.info("Best model run ID: %s", best_run_id)

    # --------------------------------------------------------
    # STEP 10: MODEL REGISTRATION
    # --------------------------------------------------------

    logger.info("[10/10] MODEL REGISTRATION")

    registration_result = register_model(best_run_id)

    if registration_result is None:
        raise RuntimeError(
            "Model registration did not return a result."
        )

    logger.info("Model registration completed.")

    # --------------------------------------------------------
    # PIPELINE COMPLETION
    # --------------------------------------------------------

    logger.info("=" * 65)
    logger.info("COMPLETE MLOPS PIPELINE EXECUTED SUCCESSFULLY")
    logger.info("=" * 65)

    return {
        "training_results": train_results,
        "evaluation_results": evaluation_results,
        "registration_result": registration_result,
    }


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    import numpy as np

    run_pipeline()
