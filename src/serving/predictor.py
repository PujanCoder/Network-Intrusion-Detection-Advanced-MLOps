import logging
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]


class Predictor:
    def __init__(self, model_path: str, preprocessor_path: str):
        self.model = joblib.load(model_path)
        bundle = joblib.load(preprocessor_path)

        self.preprocessor = bundle.get("preprocessor")
        self.feature_order = bundle["feature_order"]
        self.model_features = bundle.get("model_features")
        self.classes = list(getattr(self.model, "classes_", []))

        log.info(
            "predictor ready: input=%d, model_features=%s, classes=%s",
            len(self.feature_order),
            len(self.model_features) if self.model_features else "all",
            self.classes,
        )

    def predict(self, flow: dict) -> dict:
        row = {col: flow.get(col, np.nan) for col in self.feature_order}
        X = pd.DataFrame([row])

        if self.preprocessor is not None:
            X = self.preprocessor.transform(X)

        if self.model_features is not None:
            X = X[self.model_features]

        pred = self.model.predict(X)[0]
        out = {
            "label": str(pred),
            "is_attack": self._is_attack(pred),
            "confidence": None,
            "proba_attack": None,
        }
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X)[0]
            out["confidence"] = float(proba.max())
            out["proba_attack"] = self._attack_proba(proba)
        return out

    def _is_attack(self, pred) -> bool:
        return str(pred).lower() not in ("0", "benign", "normal", "background")

    def _attack_proba(self, proba: np.ndarray) -> float:
        for i, c in enumerate(self.classes):
            if self._is_attack(c):
                return float(proba[i])
        return 0.0


# ---- module singleton ----
_predictor: Predictor | None = None


def get_predictor() -> Predictor:
    global _predictor
    if _predictor is None:
        _predictor = Predictor(
            model_path=os.getenv(
                "IDS_MODEL_PATH", str(ROOT / "models" / "best_model.joblib")
            ),
            preprocessor_path=os.getenv(
                "IDS_PREPROCESSOR_PATH", str(ROOT / "models" / "preprocessor.joblib")
            ),
        )
    return _predictor


def predict_flow(flow: dict) -> dict:
    """Single-flow convenience wrapper used by route handlers."""
    return get_predictor().predict(flow)