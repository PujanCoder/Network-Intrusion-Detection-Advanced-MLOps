
from pathlib import Path
import json

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "raw" / "MachineLearningCSV"
REPORT_DIR = PROJECT_ROOT / "reports"

CHUNK_SIZE = 100_000


def profile_file(file_path: Path) -> dict:
    print(f"\nProfiling: {file_path.name}")

    total_rows = 0
    missing_values = {}
    infinite_values = {}
    label_counts = {}
    schema = None
    schema_consistent = True

    for chunk in pd.read_csv(
        file_path,
        chunksize=CHUNK_SIZE,
        low_memory=False
    ):
        chunk.columns = (
            chunk.columns.astype(str).str.strip()
        )

        current_schema = list(chunk.columns)

        if schema is None:
            schema = current_schema
        elif current_schema != schema:
            schema_consistent = False

        total_rows += len(chunk)

        # Missing values
        missing = chunk.isna().sum()

        for column, count in missing.items():
            missing_values[column] = (
                missing_values.get(column, 0) + int(count)
            )

        # Infinite numeric values
        numeric_data = chunk.select_dtypes(
            include=[np.number]
        )

        inf_counts = np.isinf(numeric_data).sum()

        for column, count in inf_counts.items():
            infinite_values[column] = (
                infinite_values.get(column, 0) + int(count)
            )

        # Target label distribution
        if "Label" in chunk.columns:
            labels = (
                chunk["Label"]
                .astype("string")
                .str.strip()
                .fillna("<MISSING>")
            )

            counts = labels.value_counts()

            for label, count in counts.items():
                label_counts[label] = (
                    label_counts.get(label, 0) + int(count)
                )

    return {
        "file": file_path.name,
        "rows": total_rows,
        "columns": len(schema) if schema else 0,
        "schema": schema,
        "schema_consistent": schema_consistent,
        "missing_values": missing_values,
        "infinite_values": infinite_values,
        "label_distribution": label_counts,
    }


def profile_dataset():
    if not DATA_DIR.exists():
        raise FileNotFoundError(
            f"Dataset directory not found: {DATA_DIR}"
        )

    csv_files = sorted(DATA_DIR.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {DATA_DIR}"
        )

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    reports = []

    for file_path in csv_files:
        report = profile_file(file_path)
        reports.append(report)

    # Save detailed JSON report
    json_path = REPORT_DIR / "dataset_profile.json"

    with open(json_path, "w", encoding="utf-8") as file:
        json.dump(reports, file, indent=4)

    # Save file-level summary
    summary = pd.DataFrame([
        {
            "file": report["file"],
            "rows": report["rows"],
            "columns": report["columns"],
            "schema_consistent": report["schema_consistent"],
        }
        for report in reports
    ])

    summary.to_csv(
        REPORT_DIR / "dataset_summary.csv",
        index=False
    )

    print("\n========== DATASET SUMMARY ==========")
    print(summary.to_string(index=False))

    total_rows = sum(
        report["rows"] for report in reports
    )

    print(f"\nTotal CSV files: {len(csv_files)}")
    print(f"Total records: {total_rows:,}")

    print(f"\nReports saved in: {REPORT_DIR}")


if __name__ == "__main__":
    profile_dataset()
