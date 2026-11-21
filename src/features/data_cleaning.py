from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np
from sklearn.preprocessing  import OneHotEncoder, LabelEncoder , StandardScaler , PowerTransformer
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]

DATA_PATH = (
    ROOT_DIR
    / "data"
    / "raw"
    / "MachineLearningCSV"
    / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

df = pd.read_csv(DATA_PATH)

print(f"Dataset loaded successfully: {df.shape}")

print("\nActual column names:")
for col in df.columns:
    print(repr(col))

df.columns = df.columns.str.strip()

import numpy as np
import pandas as pd

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean network intrusion detection dataset.

    Operations:
    1. Remove duplicate records.
    2. Replace infinite values with NaN.
    3. Remove rows with missing target labels.
    4. Handle missing numerical values.
    5. Handle missing categorical values.
    """

    df = df.copy()

    initial_rows = len(df)

    # 1. Remove duplicate records
    duplicates = df.duplicated().sum()
    df = df.drop_duplicates()

    # 2. Replace infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # 3. Remove rows with missing target labels
    if "Label" not in df.columns:
        raise ValueError("Target column 'Label' not found.")

    missing_labels = df["Label"].isna().sum()
    df = df.dropna(subset=["Label"])

    # 4. Identify numerical and categorical columns
    numerical_cols = df.select_dtypes(
        include=np.number
    ).columns.tolist()

    categorical_cols = df.select_dtypes(
        exclude=np.number
    ).columns.tolist()

    # 5. Handle missing numerical values
    for col in numerical_cols:
        if df[col].isna().any():
            df[col] = df[col].fillna(df[col].median())

    # 6. Handle missing categorical values
    for col in categorical_cols:
        if col != "Label" and df[col].isna().any():
            df[col] = df[col].fillna("Unknown")

    # 7. Cleaning report
    print("DATA CLEANING REPORT")
    print("-" * 35)
    print(f"Initial rows: {initial_rows}")
    print(f"Duplicates removed: {duplicates}")
    print(f"Missing labels removed: {missing_labels}")
    print(f"Final rows: {len(df)}")
    print(f"Remaining missing values: {df.isna().sum().sum()}")

    return df






def handle_outliers_iqr(
    df: pd.DataFrame,
    multiplier: float = 1.5
) -> pd.DataFrame:
    """
    Detect and treat numerical outliers using IQR capping.

    - Detects outliers using IQR.
    - Caps values below the lower bound.
    - Caps values above the upper bound.
    - Excludes the target Label column.
    - Preserves all records.
    """

    df = df.copy()

    numerical_cols = df.select_dtypes(
        include="number"
    ).columns.drop("Label", errors="ignore")

    report = []

    for col in numerical_cols:

        q1 = df[col].quantile(0.25)
        q3 = df[col].quantile(0.75)

        iqr = q3 - q1

        lower_bound = q1 - multiplier * iqr
        upper_bound = q3 + multiplier * iqr

        outlier_mask = (
            (df[col] < lower_bound) |
            (df[col] > upper_bound)
        )

        outlier_count = outlier_mask.sum()

        # Treat outliers using IQR capping
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

    report_df = pd.DataFrame(report)

    print("OUTLIER HANDLING REPORT")
    print("-" * 50)
    print(report_df.to_string(index=False))
    print("-" * 50)
    print(f"Total records preserved: {len(df)}")

    return df, report_df
# STEP 1: Execute data cleaning
cleaned_df = clean_data(df)

# STEP 2: Execute outlier detection and treatment
processed_df, outlier_report = handle_outliers_iqr(cleaned_df)


print("Missing values:", processed_df.isnull().sum().sum())

print("Duplicates:", processed_df.duplicated().sum())

print(
    "Infinite values:",
    np.isinf(
        processed_df.select_dtypes(include=np.number)
    ).sum().sum()
)

print("Final shape:", processed_df.shape)
# Save cleaned dataset

OUTPUT_PATH = ROOT_DIR / "data" / "processed" / "cleaned_dataset.csv"

OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

processed_df.to_csv(OUTPUT_PATH, index=False)

print(f"Cleaned dataset saved: {OUTPUT_PATH}")