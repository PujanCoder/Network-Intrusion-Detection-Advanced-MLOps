
import pandas as pd
from sklearn.model_selection import train_test_split
from evidently import Report
from evidently.presets import DataDriftPreset
from pathlib import Path

def split_data(
    df: pd.DataFrame,
    target_column: str = "Label",
    test_size: float = 0.20,
    random_state: int = 42
):
    """
    Split dataset into training and testing sets.

    - 80% training data
    - 20% testing data
    - Stratified splitting to preserve class distribution
    """

    if target_column not in df.columns:
        raise ValueError(
            f"Target column '{target_column}' not found."
        )

    X = df.drop(columns=[target_column])
    y = df[target_column]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )

    print("DATA SPLITTING REPORT")
    print("-" * 40)
    print(f"Total samples: {len(df)}")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    print(f"Training percentage: {len(X_train)/len(df)*100:.2f}%")
    print(f"Testing percentage: {len(X_test)/len(df)*100:.2f}%")

    print("\nTraining class distribution:")
    print(y_train.value_counts(normalize=True))

    print("\nTesting class distribution:")
    print(y_test.value_counts(normalize=True))

    return X_train, X_test, y_train, y_test

def validate_data_drift(
    reference_data: pd.DataFrame,
    current_data: pd.DataFrame
):

    report = Report([
        DataDriftPreset()
    ])

    snapshot = report.run(
        current_data=current_data,
        reference_data=reference_data
    )

    return snapshot




# ==========================================
# EXECUTION
# ==========================================

ROOT_DIR = Path(__file__).resolve().parents[2]

DATA_PATH = (
    ROOT_DIR
    / "data"
    / "processed"
    / "cleaned_dataset.csv"
)

# 1. Load cleaned dataset
df = pd.read_csv(DATA_PATH)

print(f"Dataset loaded: {df.shape}")

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

# 4. Save report
REPORT_PATH = ROOT_DIR / "reports" / "data_drift_report.html"
REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

snapshot.save_html(str(REPORT_PATH))

print("\nData drift validation completed.")
print(f"Report saved at: {REPORT_PATH}")