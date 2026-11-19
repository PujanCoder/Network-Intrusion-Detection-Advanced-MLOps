import hashlib
import re
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import numpy as np

from pymongo import UpdateOne

from src.database.mongodb import raw_flows, client


PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIRECTORY = (
    PROJECT_ROOT / "data" / "raw" / "MachineLearningCSV"
)

BATCH_SIZE = 2000
TARGET_FILES = [
    path.name
    for path in sorted(DATA_DIRECTORY.glob("*.csv"))
]
def normalize_columns(columns):
    """
    Convert CSV column names into MongoDB-safe field names.
    """

    normalized = []
    seen = {}

    for column in columns:

        name = column.strip().lower()

        # Replace special characters with underscores.
        name = re.sub(r"[^a-z0-9]+", "_", name)

        name = name.strip("_")

        # Handle duplicate normalized column names.
        count = seen.get(name, 0)

        if count > 0:
            name = f"{name}_duplicate_{count}"

        seen[name] = count + 1

        normalized.append(name)

    return normalized


def make_bson_safe(value):
    """
    Convert Pandas and NumPy values into BSON-compatible values.
    """

    if pd.isna(value):
        return None

    if isinstance(value, np.generic):
        return value.item()

    return value


def ingest_file(csv_path):

    print(f"\nProcessing: {csv_path.name}")

    total_rows = 0
    total_inserted = 0

    for chunk_number, chunk in enumerate(
        pd.read_csv(csv_path, chunksize=BATCH_SIZE)
    ):

        # Normalize column names before MongoDB insertion.
        chunk.columns = normalize_columns(chunk.columns)

        operations = []

        timestamp = datetime.now(timezone.utc)

        records = chunk.to_dict(orient="records")

        for offset, row in enumerate(records):

            source_row = (
                chunk_number * BATCH_SIZE + offset + 1
            )

            # Generate deterministic document ID.
            record_id = hashlib.sha256(
                f"CIC-IDS2017:{csv_path.name}:{source_row}".encode()
            ).hexdigest()

            document = {
                key: make_bson_safe(value)
                for key, value in row.items()
            }

            document["_id"] = record_id

            document["_metadata"] = {
                "source": "CIC-IDS2017",
                "source_file": csv_path.name,
                "source_row": source_row,
                "ingested_at": timestamp
            }

            operations.append(
                UpdateOne(
                    {"_id": record_id},
                    {"$setOnInsert": document},
                    upsert=True
                )
            )

        if operations:

            result = raw_flows.bulk_write(
                operations,
                ordered=False
            )

            total_inserted += result.upserted_count

        total_rows += len(chunk)

        print(
            f"Processed: {total_rows:,} | "
            f"Inserted: {total_inserted:,}"
        )

    print(f"\nCompleted: {csv_path.name}")

    return total_rows, total_inserted


def main():

    for filename in TARGET_FILES:

        csv_path = DATA_DIRECTORY / filename

        if not csv_path.exists():
            raise FileNotFoundError(
                f"Dataset file not found: {csv_path}"
            )

        ingest_file(csv_path)

    print("\nInitial ingestion test completed!")
def normalize_columns(columns):
    """
    Convert CSV column names into unique MongoDB-safe field names.
    """

    normalized = []
    seen = {}

    for column in columns:

        base = re.sub(
            r"[^a-z0-9]+",
            "_",
            str(column).strip().lower()
        ).strip("_")

        count = seen.get(base, 0)

        if count == 0:
            final_name = base
        else:
            final_name = f"{base}_duplicate_{count}"

        seen[base] = count + 1

        normalized.append(final_name)

    return normalized

if __name__ == "__main__":

    try:
        main()

    finally:
        client.close()