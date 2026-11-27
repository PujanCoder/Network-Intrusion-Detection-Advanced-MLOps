"""Model-facing service used by the API layer.

Separates "what the model is" (artifact metadata) from "how it is behaving"
(runtime counters in SQLite), and keeps the original CICIDS2017 batch model
card clearly distinct from the live Zeek flow classifier.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.realtime.config import PROJECT_ROOT
from src.realtime.model import ZeekModel
from src.realtime.store import Store

TRAINING_RESULTS = PROJECT_ROOT / "reports" / "training_results.json"
EVALUATION_RESULTS = PROJECT_ROOT / "reports" / "model_evaluation" / "evaluation_results.json"


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


class ModelService:
    def __init__(self, model: ZeekModel, store: Store) -> None:
        self.model = model
        self.store = store

    # ------------------------------------------------------------------ #
    def batch_model_card(self) -> dict[str, Any]:
        """The offline CICIDS2017 pipeline model (separate from the Zeek model)."""

        training = _read_json(TRAINING_RESULTS) or {}
        evaluation = _read_json(EVALUATION_RESULTS) or {}
        return {
            "kind": "batch",
            "name": "CICIDS2017 batch classifier",
            "task": "binary DDoS vs BENIGN on the CICIDS2017 Friday DDoS capture",
            "best_model": training.get("best_model"),
            "training_results_available": bool(training),
            "evaluation_results_available": bool(evaluation),
            "validation_metrics": training.get("validation_metrics", {}),
            "test_metrics": evaluation.get("test_metrics", {}),
            "confusion_matrix": evaluation.get("confusion_matrix"),
            "notes": [
                "Trained and evaluated on a single CICIDS2017 capture day.",
                "Near-perfect scores on that day are expected and do not imply real-world performance.",
                "Served by the offline DVC/MLflow pipeline, not by the live sensor path.",
            ],
        }

    # ------------------------------------------------------------------ #
    def info(self) -> dict[str, Any]:
        metadata = self.model.info()
        counts = self.store.prediction_counts()
        overview = self.store.overview()
        return {
            "live_model": {
                "kind": "realtime",
                "name": metadata.get("model_name"),
                "version": metadata.get("model_version"),
                "algorithm": metadata.get("algorithm"),
                "trained_at": metadata.get("trained_at"),
                "loaded": metadata.get("loaded"),
                "load_error": metadata.get("load_error"),
                "artifact_path": metadata.get("artifact_path"),
                "threshold": metadata.get("threshold"),
                "target_false_positive_rate": metadata.get("target_false_positive_rate"),
                "training_datasets": metadata.get("training_datasets"),
                "dataset_distribution": metadata.get("dataset_distribution"),
                "row_counts": metadata.get("row_counts"),
                "label_distribution": metadata.get("label_distribution"),
                "classes": metadata.get("classes"),
                "feature_schema": metadata.get("feature_schema"),
                "top_features": metadata.get("top_features"),
                "metrics": {
                    "validation": metadata.get("validation_metrics"),
                    "test": metadata.get("test_metrics"),
                    "official_test_partitions": metadata.get("holdout_metrics"),
                    "cross_dataset": metadata.get("cross_dataset"),
                },
                "latency": metadata.get("latency"),
                "candidates": metadata.get("candidates"),
                "environment": metadata.get("environment"),
                "notes": metadata.get("notes", []),
            },
            "runtime": {
                "predictions": int(sum(counts.values()) - counts.get("UNCLASSIFIED", 0)),
                "prediction_count_by_label": counts,
                "unclassified_events": int(counts.get("UNCLASSIFIED", 0)),
                "total_events": int(overview["total_events"]),
                "model_errors": int(overview["model_errors"]),
                "dead_letters": int(overview["dead_letters"]),
                "avg_prediction_latency_ms": overview["avg_prediction_latency_ms"],
                "latency_percentiles": self.store.prediction_latency(),
                "confidence_histogram": self.store.confidence_histogram(),
                "predictions_per_second": overview["predictions_per_second"],
            },
            "batch_model": self.batch_model_card(),
        }
