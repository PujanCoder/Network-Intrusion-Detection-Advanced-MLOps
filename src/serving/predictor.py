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
_predictor_error: str | None = None
_predictor_attempted = False


class PredictorUnavailable(RuntimeError):
    """Raised when the CICIDS artefacts are missing or unusable."""


def _paths() -> tuple[str, str]:
    return (
        os.getenv("IDS_MODEL_PATH", str(ROOT / "models" / "best_model.joblib")),
        os.getenv("IDS_PREPROCESSOR_PATH", str(ROOT / "models" / "preprocessor.joblib")),
    )


def load_predictor() -> tuple[Predictor | None, str | None]:
    """Load once; return the predictor and the recorded failure reason, if any.

    The batch artefacts are DVC-tracked and therefore absent from a plain git
    deployment. That must not crash the process: the Zeek path keeps working and
    the failure is reported by ``/api/v1/health`` and ``/api/v1/ready``.
    """

    global _predictor, _predictor_error, _predictor_attempted
    if _predictor is not None:
        return _predictor, None
    if _predictor_attempted:
        return None, _predictor_error
    _predictor_attempted = True
    model_path, preprocessor_path = _paths()
    try:
        _predictor = Predictor(model_path=model_path, preprocessor_path=preprocessor_path)
        _predictor_error = None
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        _predictor_error = f"{type(exc).__name__}: {exc}"
        log.error(
            "CICIDS predictor unavailable (model=%s preprocessor=%s): %s",
            model_path,
            preprocessor_path,
            _predictor_error,
        )
    return _predictor, _predictor_error


def get_predictor() -> Predictor:
    predictor, error = load_predictor()
    if predictor is None:
        raise PredictorUnavailable(error or "predictor could not be loaded")
    return predictor


def predictor_state() -> dict[str, object]:
    model_path, preprocessor_path = _paths()
    return {
        "loaded": _predictor is not None,
        "model_path": model_path,
        "preprocessor_path": preprocessor_path,
        "model_exists": Path(model_path).exists(),
        "preprocessor_exists": Path(preprocessor_path).exists(),
        "error": _predictor_error,
    }


def reset_predictor() -> None:
    """Drop the cached state (tests and after deploying new artefacts)."""

    global _predictor, _predictor_error, _predictor_attempted
    _predictor = None
    _predictor_error = None
    _predictor_attempted = False


def predict_flow(flow: dict) -> dict:
    """Single-flow convenience wrapper used by route handlers."""
    return get_predictor().predict(flow)
