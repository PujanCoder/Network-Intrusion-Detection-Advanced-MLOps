from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from src.features.zeek.conn import CONN_FEATURE_NAMES

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "processed" / "zeek" / "zeek_conn_lab_dataset.csv"
OUT_DIR = ROOT / "models" / "zeek"
REPORT_DIR = ROOT / "reports" / "zeek"


def train():
    if not DATA.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA}")
    df = pd.read_csv(DATA)
    missing = [c for c in CONN_FEATURE_NAMES + ["label"] if c not in df.columns]
    if missing:
        raise ValueError(f"Missing columns: {missing}")

    X = df[CONN_FEATURE_NAMES].astype(float)
    y = df["label"].astype(str)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
    model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    report = classification_report(y_test, preds, output_dict=True, zero_division=0)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    artifact = {
        "model": model,
        "feature_names": CONN_FEATURE_NAMES,
        "schema_version": "zeek_conn_v1",
        "label_column": "label",
        "classes": list(model.classes_),
        "dataset": str(DATA.relative_to(ROOT)),
        "dataset_rows": int(len(df)),
        "training_note": "Lab baseline trained on synthetic Zeek conn feature dataset for pipeline demonstration; not production-grade.",
    }
    joblib.dump(artifact, OUT_DIR / "zeek_conn_model.joblib")
    (REPORT_DIR / "zeek_conn_training_report.json").write_text(json.dumps({
        "schema_version": "zeek_conn_v1",
        "feature_names": CONN_FEATURE_NAMES,
        "classes": list(model.classes_),
        "dataset": str(DATA.relative_to(ROOT)),
        "rows": int(len(df)),
        "report": report,
        "note": artifact["training_note"],
    }, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "classes": list(model.classes_), "rows": len(df), "test_accuracy": report["accuracy"]}, indent=2))


if __name__ == "__main__":
    train()
