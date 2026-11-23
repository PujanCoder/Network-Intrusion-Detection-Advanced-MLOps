
import pandas as pd
from pathlib import Path

from src.features.data_cleaning import clean_data


# ============================================================
# PROJECT PATHS
# ============================================================

ROOT_DIR = Path(__file__).resolve().parents[2]

RAW_DATA_PATH = (
    ROOT_DIR
    / "data"
    / "raw"
    / "MachineLearningCSV"
    / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
)

PROCESSED_DATA_PATH = (
    ROOT_DIR
    / "data"
    / "processed"
    / "cleaned_dataset.csv"
)


# ============================================================
# DATA PIPELINE
# ============================================================

def run_pipeline():

    print("\n" + "=" * 55)
    print("NETWORK INTRUSION DETECTION PIPELINE")
    print("=" * 55)

    # STEP 1: LOAD RAW DATA
    print("\n[STEP 1] Loading raw dataset...")

    if not RAW_DATA_PATH.exists():
        raise FileNotFoundError(
            f"Raw dataset not found: {RAW_DATA_PATH}"
        )

    df = pd.read_csv(RAW_DATA_PATH)

    print(f"Dataset loaded successfully: {df.shape}")

    # STEP 2: DATA CLEANING
    print("\n[STEP 2] Cleaning dataset...")

    df = clean_data(df)

    print(f"Shape after cleaning: {df.shape}")

    # STEP 3: SAVE CLEANED DATA
    print("\n[STEP 3] Saving cleaned dataset...")

    PROCESSED_DATA_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(PROCESSED_DATA_PATH, index=False)

    print(f"Cleaned dataset saved to: {PROCESSED_DATA_PATH}")

    print("\n" + "=" * 55)
    print("PIPELINE COMPLETED")
    print("=" * 55)


if __name__ == "__main__":
    run_pipeline()
