
import logging
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split


ROOT_DIR = Path(__file__).resolve().parents[2]

DATA_PATH = (
    ROOT_DIR
    / "data"
    / "processed"
    / "cleaned_dataset.csv"
)

REPORT_PATH = (
    ROOT_DIR
    / "reports"
    / "data_drift_report.html"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def split_data(
    df: pd.DataFrame,
    target_column: str = "Label",
    test_size: float = 0.20,
    random_state: int = 42
):
    """
    Split the dataset into training and testing sets.

    - 80% training data by default
    - 20% testing data by default
    - Stratified splitting preserves class distribution
    """

    if not isinstance(df, pd.DataFrame):
        raise TypeError("Input must be a pandas DataFrame.")

    if target_column not in df.columns:
        raise ValueError(
            f"Target column '{target_column}' not found."
        )

    if not 0 < test_size < 1:
        raise ValueError("test_size must be between 0 and 1.")

    X = df.drop(columns=[target_column])
    y = df[target_column]

    if y.isna().any():
        raise ValueError(
            f"Target column '{target_column}' contains missing values."
        )

    if y.nunique() < 2:
        raise ValueError(
            "At least two target classes are required for stratified splitting."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    logger.info("DATA SPLITTING REPORT")
    logger.info("-" * 40)
    logger.info("Total samples: %s", len(df))
    logger.info("Training samples: %s", len(X_train))
    logger.info("Testing samples: %s", len(X_test))
    logger.info(
        "Training percentage: %.2f%%",
        len(X_train) / len(df) * 100
    )
    logger.info(
        "Testing percentage: %.2f%%",
        len(X_test) / len(df) * 100
    )

    logger.info("Training class distribution:\n%s",
                y_train.value_counts(normalize=True))

    logger.info("Testing class distribution:\n%s",
                y_test.value_counts(normalize=True))

    return X_train, X_test, y_train, y_test


def validate_data_drift(
    reference_data: pd.DataFrame,
    current_data: pd.DataFrame
):
    """
    Generate an Evidently data drift report.

    reference_data: Training features
    current_data: Testing features
    """

    # Import only when drift validation is actually requested.
    from evidently import Report
    from evidently.presets import DataDriftPreset

    report = Report([
        DataDriftPreset()
    ])

    snapshot = report.run(
        current_data=current_data,
        reference_data=reference_data
    )

    return snapshot


def main():
    """
    Execute the preprocessing and data drift validation workflow.
    """

    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Cleaned dataset not found: {DATA_PATH}"
        )

    # 1. Load cleaned dataset
    df = pd.read_csv(DATA_PATH)

    logger.info("Dataset loaded: %s", df.shape)

    # 2. Split dataset
    X_train, X_test, y_train, y_test = split_data(
        df,
        target_column="Label",
        test_size=0.20,
        random_state=42
    )

    # 3. Validate feature distribution using Evidently
    snapshot = validate_data_drift(
        reference_data=X_train,
        current_data=X_test
    )

    # 4. Save drift report
    REPORT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    snapshot.save_html(str(REPORT_PATH))

    logger.info("Data drift validation completed.")
    logger.info("Report saved at: %s", REPORT_PATH)


if __name__ == "__main__":
    main()
