
import logging
from pathlib import Path

import numpy as np
import pandas as pd


ROOT_DIR = Path(__file__).resolve().parents[2]

DATA_PATH = (
    ROOT_DIR
    / "data"
    / "raw"
    / "MachineLearningCSV"
    / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

OUTPUT_PATH = (
    ROOT_DIR
    / "data"
    / "processed"
    / "cleaned_dataset.csv"
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean the network intrusion detection dataset.

    Operations:
    1. Remove duplicate records.
    2. Replace infinite values with NaN.
    3. Remove rows with missing target labels.
    4. Handle missing numerical values.
    5. Handle missing categorical values.
    """

    if not isinstance(df, pd.DataFrame):
        raise TypeError("Input must be a pandas DataFrame.")

    df = df.copy()
    initial_rows = len(df)

    # 1. Normalize column names
    df.columns = (
        df.columns
        .str.replace("\ufeff", "", regex=False)
        .str.strip()
    )

    # 2. Remove duplicate records
    duplicates = int(df.duplicated().sum())
    df = df.drop_duplicates()

    # 3. Replace infinite values with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # 4. Remove rows with missing target labels
    if "Label" not in df.columns:
        raise ValueError("Target column 'Label' not found.")

    missing_labels = int(df["Label"].isna().sum())
    df = df.dropna(subset=["Label"])

    # 5. Identify numerical and categorical columns
    numerical_cols = df.select_dtypes(
        include=np.number
    ).columns.tolist()

    categorical_cols = df.select_dtypes(
        exclude=np.number
    ).columns.tolist()

    # 6. Handle missing numerical values
    for col in numerical_cols:
        if df[col].isna().any():
            median_value = df[col].median()
            df[col] = df[col].fillna(median_value)

    # 7. Handle missing categorical values
    for col in categorical_cols:
        if col != "Label" and df[col].isna().any():
            df[col] = df[col].fillna("Unknown")

    # 8. Cleaning report
    logger.info("DATA CLEANING REPORT")
    logger.info("-" * 35)
    logger.info("Initial rows: %s", initial_rows)
    logger.info("Duplicates removed: %s", duplicates)
    logger.info("Missing labels removed: %s", missing_labels)
    logger.info("Final rows: %s", len(df))
    logger.info("Remaining missing values: %s", df.isna().sum().sum())

    return df


def handle_outliers_iqr(
    df: pd.DataFrame,
    multiplier: float = 1.5
):
    """
    Detect and cap numerical outliers using the IQR method.

    Binary features and features with zero IQR are skipped.
    The number of rows is preserved.
    """

    if not isinstance(df, pd.DataFrame):
        raise TypeError("Input must be a pandas DataFrame.")

    if multiplier <= 0:
        raise ValueError("Multiplier must be greater than zero.")

    df = df.copy()

    numerical_cols = df.select_dtypes(
        include="number"
    ).columns.drop("Label", errors="ignore")

    report = []

    for col in numerical_cols:

        # Skip binary features
        if df[col].nunique() <= 2:
            continue

        q1 = df[col].quantile(0.25)
        q3 = df[col].quantile(0.75)

        iqr = q3 - q1

        # Skip zero-IQR features
        if iqr == 0:
            continue

        lower_bound = q1 - multiplier * iqr
        upper_bound = q3 + multiplier * iqr

        outlier_mask = (
            (df[col] < lower_bound)
            | (df[col] > upper_bound)
        )

        outlier_count = int(outlier_mask.sum())

        df[col] = df[col].clip(
            lower=lower_bound,
            upper=upper_bound
        )

        report.append({
            "Feature": col,
            "Outliers Detected": outlier_count,
            "Outliers Treated": outlier_count,
            "Lower Bound": lower_bound,
            "Upper Bound": upper_bound
        })

    report_df = pd.DataFrame(
        report,
        columns=[
            "Feature",
            "Outliers Detected",
            "Outliers Treated",
            "Lower Bound",
            "Upper Bound"
        ]
    )

    logger.info("OUTLIER HANDLING REPORT")
    logger.info("-" * 50)

    if not report_df.empty:
        logger.info("\n%s", report_df.to_string(index=False))
    else:
        logger.info("No eligible numerical features required outlier treatment.")

    logger.info("Total records preserved: %s", len(df))

    return df, report_df


def main():
    """
    Execute the complete data-cleaning workflow.
    """

    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Raw dataset not found: {DATA_PATH}"
        )

    # 1. Load raw dataset
    df = pd.read_csv(DATA_PATH)

    logger.info("Dataset loaded successfully: %s", df.shape)

    logger.info("Actual column names:")
    for col in df.columns:
        logger.info("%r", col)

    # 2. Clean dataset
    cleaned_df = clean_data(df)

    # 3. Handle outliers
    processed_df, outlier_report = handle_outliers_iqr(
        cleaned_df
    )

    # 4. Validate cleaned dataset
    missing_values = processed_df.isnull().sum().sum()
    duplicates = processed_df.duplicated().sum()

    infinite_values = np.isinf(
        processed_df.select_dtypes(include=np.number)
    ).sum().sum()

    logger.info("Missing values: %s", missing_values)
    logger.info("Duplicates: %s", duplicates)
    logger.info("Infinite values: %s", infinite_values)
    logger.info("Final shape: %s", processed_df.shape)

    # 5. Save cleaned dataset
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    processed_df.to_csv(
        OUTPUT_PATH,
        index=False
    )

    logger.info("Cleaned dataset saved: %s", OUTPUT_PATH)


if __name__ == "__main__":
    main()
