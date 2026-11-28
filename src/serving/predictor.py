"""CICIDS2017 batch scorer for the serving app.

Two artefacts make up the batch model - the estimator and the preprocessor
bundle that produced its feature matrix - and both live in DVC, so a plain git
deployment usually has neither. Loading therefore has to satisfy three rules:

* paths resolve against the repository root, never against the process cwd;
* each file is checked and reported separately, so the error names the file that
  is actually missing;
* failure is recorded, never raised at import time, because the Zeek path must
  keep scoring in a deployment without these artefacts.

"Loaded" means more than "the file opened": the pair is smoke-tested with a
single all-zero flow, which is the same contract
``src/serving/validate_artifacts.py`` checks offline.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = ROOT / "models" / "best_model.joblib"
DEFAULT_PREPROCESSOR_PATH = ROOT / "models" / "preprocessor.joblib"
FETCH_HINT = "python scripts/fetch_models.py"


class ArtifactError(RuntimeError):
    """A single artefact is missing, empty, unreadable or incompatible."""

    def __init__(self, kind: str, path: Path, detail: str) -> None:
        self.kind = kind
        self.path = Path(path)
        self.detail = detail
        hint = f"run `{FETCH_HINT}`" if kind in {"missing", "empty"} else "retrain or re-pull the artefact"
        super().__init__(f"{self.path} ({detail}); {hint}")


def resolve_path(env_var: str, default: Path) -> Path:
    configured = os.getenv(env_var)
    path = Path(configured) if configured else default
    return path if path.is_absolute() else (ROOT / path)


def _describe(path: Path) -> dict[str, Any]:
    exists = path.is_file()
    state: dict[str, Any] = {"path": str(path), "exists": exists, "bytes": 0, "sha256": None}
    if not exists:
        return state
    state["bytes"] = path.stat().st_size
    if state["bytes"] > 0:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        state["sha256"] = digest.hexdigest()[:16]
    return state


def _load_joblib(path: Path, label: str) -> Any:
    if not path.is_file():
        raise ArtifactError("missing", path, f"{label} not found")
    if path.stat().st_size == 0:
        raise ArtifactError("empty", path, f"{label} is empty")
    try:
        return joblib.load(path)
    except Exception as exc:  # noqa: BLE001 - surfaced verbatim in the health payload
        raise ArtifactError("invalid", path, f"{label} could not be deserialised: {exc}") from exc


class Predictor:
    def __init__(self, model_path: str | os.PathLike[str], preprocessor_path: str | os.PathLike[str]):
        self.model_path = Path(model_path)
        self.preprocessor_path = Path(preprocessor_path)

        self.model = _load_joblib(self.model_path, "batch model")
        bundle = _load_joblib(self.preprocessor_path, "preprocessor bundle")
        if not isinstance(bundle, dict) or "feature_order" not in bundle:
            raise ArtifactError(
                "invalid", self.preprocessor_path, "preprocessor bundle has no feature_order"
            )

        self.preprocessor = bundle.get("preprocessor")
        self.feature_order = list(bundle["feature_order"])
        self.model_features = bundle.get("model_features")
        self.classes = [str(c) for c in getattr(self.model, "classes_", [])]
        self.output_order = bundle.get("output_order")
        self.metadata = bundle.get("metadata") or {}

        self._smoke_test()

        self.version = str(
            bundle.get("model_version") or self.metadata.get("version") or self._derived_version()
        )
        self.trained_at = bundle.get("trained_at") or self.metadata.get("trained_at")
        self.estimator = type(self.model).__name__
        self.loaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        log.info(
            "cicids predictor ready: estimator=%s version=%s input_features=%d "
            "model_features=%s classes=%s",
            self.estimator,
            self.version,
            len(self.feature_order),
            len(self.model_features) if self.model_features else "all",
            self.classes,
        )

    def _derived_version(self) -> str:
        """Stable version from the artefact bytes, so swapping a file is visible."""

        digest = hashlib.sha256()
        for path in (self.model_path, self.preprocessor_path):
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    digest.update(chunk)
        return f"sha256:{digest.hexdigest()[:12]}"

    def _sanitise(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Bring a raw capture into the numeric, finite space the transformer expects.

        CICIDS rows carry ``inf`` in the rate features when duration is 0
        (``Flow Bytes/s``, ``Flow Packets/s``); the training pipeline replaced
        non-finite values with the column median before fitting, but the bundle
        does not carry those medians. Serving substitutes 0.0, which the fitted
        transformer accepts and which reads as "no measurable rate" for an
        undefined one. Missing or non-numeric fields are treated the same way.
        """

        numeric = frame.apply(pd.to_numeric, errors="coerce")
        return numeric.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    def _transform(self, frame: pd.DataFrame) -> Any:
        prepared = self._sanitise(frame)
        transformed = self.preprocessor.transform(prepared) if self.preprocessor is not None else prepared
        if self.model_features is not None:
            transformed = transformed[self.model_features]
        return transformed

    def _smoke_test(self) -> None:
        """Prove the pair can score before it is reported as loaded."""

        if not self.feature_order:
            raise ArtifactError("invalid", self.preprocessor_path, "feature_order is empty")
        sample = pd.DataFrame([{column: 0.0 for column in self.feature_order}])
        try:
            self.model.predict(self._transform(sample))
        except Exception as exc:  # noqa: BLE001
            raise ArtifactError(
                "invalid",
                self.preprocessor_path,
                f"preprocessor/model contract mismatch: {type(exc).__name__}: {exc}",
            ) from exc

    def predict(self, flow: dict) -> dict:
        row = {column: flow.get(column, np.nan) for column in self.feature_order}
        X = self._transform(pd.DataFrame([row]))

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
        for index, label in enumerate(self.classes):
            if self._is_attack(label):
                return float(proba[index])
        return 0.0


# ---- module singleton ----
_predictor: Predictor | None = None
_predictor_error: str | None = None
_predictor_error_kind: str | None = None
_predictor_attempted = False
_attempted_at: str | None = None


class PredictorUnavailable(RuntimeError):
    """Raised when the CICIDS artefacts are missing or unusable."""


def _paths() -> tuple[Path, Path]:
    return (
        resolve_path("IDS_MODEL_PATH", DEFAULT_MODEL_PATH),
        resolve_path("IDS_PREPROCESSOR_PATH", DEFAULT_PREPROCESSOR_PATH),
    )


def load_predictor() -> tuple[Predictor | None, str | None]:
    """Load once; return the predictor and the recorded failure reason, if any.

    The batch artefacts are DVC-tracked and therefore absent from a plain git
    deployment. That must not crash the process: the Zeek path keeps working and
    the failure is reported by ``/api/v1/health`` and ``/api/v1/ready``.
    """

    global _predictor, _predictor_error, _predictor_error_kind, _predictor_attempted, _attempted_at
    if _predictor is not None:
        return _predictor, None
    if _predictor_attempted:
        return None, _predictor_error
    _predictor_attempted = True
    _attempted_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    model_path, preprocessor_path = _paths()
    try:
        _predictor = Predictor(model_path=model_path, preprocessor_path=preprocessor_path)
        _predictor_error = None
        _predictor_error_kind = None
    except ArtifactError as exc:
        _predictor_error = str(exc)
        _predictor_error_kind = exc.kind
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        _predictor_error = f"{type(exc).__name__}: {exc}"
        _predictor_error_kind = "invalid"
    if _predictor is None:
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
    """Everything the UI needs to tell "loaded" from "absent", with evidence."""

    model_path, preprocessor_path = _paths()
    predictor = _predictor
    return {
        "loaded": predictor is not None,
        "error": _predictor_error,
        "error_kind": _predictor_error_kind,
        "model_path": str(model_path),
        "preprocessor_path": str(preprocessor_path),
        "model_exists": model_path.is_file(),
        "preprocessor_exists": preprocessor_path.is_file(),
        "checked_at": _attempted_at,
        "loaded_at": predictor.loaded_at if predictor else None,
        "version": predictor.version if predictor else None,
        "estimator": predictor.estimator if predictor else None,
        "trained_at": predictor.trained_at if predictor else None,
        "features": len(predictor.feature_order) if predictor else None,
        "model_features": (
            len(predictor.model_features) if predictor and predictor.model_features else None
        ),
        "classes": predictor.classes if predictor else [],
        "artifacts": {"model": _describe(model_path), "preprocessor": _describe(preprocessor_path)},
        "remediation": None if predictor else f"{FETCH_HINT} or set IDS_MODEL_PATH / IDS_PREPROCESSOR_PATH",
    }


def reset_predictor() -> None:
    """Drop the cached state (tests, and after deploying new artefacts)."""

    global _predictor, _predictor_error, _predictor_error_kind, _predictor_attempted, _attempted_at
    _predictor = None
    _predictor_error = None
    _predictor_error_kind = None
    _predictor_attempted = False
    _attempted_at = None


def predict_flow(flow: dict) -> dict:
    """Single-flow convenience wrapper used by route handlers."""
    return get_predictor().predict(flow)
