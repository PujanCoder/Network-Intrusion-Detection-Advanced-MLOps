from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from src.features.zeek.conn import CONN_FEATURE_NAMES, extract_conn_features

log = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[2]


class ZeekConnPredictor:
    def __init__(self, model_path: Path):
        bundle = joblib.load(model_path)
        self.model = bundle["model"]
        self.feature_names = bundle.get("feature_names", CONN_FEATURE_NAMES)
        self.schema_version = bundle.get("schema_version", "zeek_conn_v1")
        self.classes = [str(c) for c in getattr(self.model, "classes_", bundle.get("classes", []))]
        self.training_note = bundle.get("training_note")

    def predict_from_conn(self, normalized: dict[str, Any], *, proto: str | None = None, service: str | None = None) -> dict[str, Any]:
        feat = extract_conn_features(normalized, proto=proto, service=service)
        X = pd.DataFrame([[feat[c] for c in self.feature_names]], columns=self.feature_names)
        pred = self.model.predict(X)[0]
        out = {
            "label": str(pred),
            "schema_version": self.schema_version,
            "confidence": None,
            "probabilities": None,
            "is_attack": str(pred).upper() not in {"BENIGN", "NORMAL"},
            "status": "scored",
        }
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X)[0]
            prob_map = {str(c): float(p) for c, p in zip(self.classes, probs)}
            out["confidence"] = float(max(probs))
            out["probabilities"] = prob_map
        return out


_zeek_predictor: ZeekConnPredictor | None = None
_zeek_predictor_checked = False


def get_zeek_predictor() -> ZeekConnPredictor | None:
    global _zeek_predictor, _zeek_predictor_checked
    if _zeek_predictor_checked:
        return _zeek_predictor
    _zeek_predictor_checked = True
    path = ROOT / "models" / "zeek" / "zeek_conn_model.joblib"
    if not path.exists():
        log.warning("Zeek model not found at %s; Zeek events will be UNCLASSIFIED until trained model is available", path)
        _zeek_predictor = None
        return None
    try:
        _zeek_predictor = ZeekConnPredictor(path)
        log.info("Loaded Zeek model: %s classes=%s", path, _zeek_predictor.classes)
    except Exception:  # noqa: BLE001
        log.exception("Failed to load Zeek model at %s", path)
        _zeek_predictor = None
    return _zeek_predictor


def predict_zeek_event(log_type: str, normalized: dict[str, Any], *, proto: str | None = None, service: str | None = None) -> dict[str, Any]:
    if log_type != "conn":
        return {
            "label": "UNCLASSIFIED",
            "status": "unscored",
            "reason": f"no Zeek ML model scoring for log_type={log_type} in Phase 2 baseline",
            "is_attack": False,
            "confidence": None,
            "probabilities": None,
        }
    predictor = get_zeek_predictor()
    if predictor is None:
        return {
            "label": "UNCLASSIFIED",
            "status": "unscored",
            "reason": "Zeek-compatible model artifact not available",
            "is_attack": False,
            "confidence": None,
            "probabilities": None,
        }
    return predictor.predict_from_conn(normalized, proto=proto, service=service)
