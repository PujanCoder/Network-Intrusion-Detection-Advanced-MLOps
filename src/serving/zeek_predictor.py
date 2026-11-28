"""Zeek-compatible flow classifier used by the serving app.

The CICIDS baseline stays untouched: Zeek events are scored by a separate model
with its own schema. The critical property is that the *same* code that trained
the model builds the vector at inference time (``src.realtime.features``). The
earlier implementation used a second, divergent 25-feature layout that no
committed artefact was trained with, so nothing could ever be scored.
"""

from __future__ import annotations

import logging
import math
import os
from pathlib import Path
from typing import Any, Mapping

import joblib
import numpy as np

from src.realtime.features import FEATURE_ORDER, features_from_zeek
from src.realtime.zeek_parser import NormalizedEvent

log = logging.getLogger(__name__)
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_PATH = ROOT / "models" / "zeek" / "zeek_model.joblib"

UNCLASSIFIED = "UNCLASSIFIED"


def _num(value: Any) -> float | None:
    if value is None or value == "" or value == "-":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(number) else number


def _int(value: Any) -> int | None:
    number = _num(value)
    return None if number is None else int(number)


def resolve_model_path(configured: Path | str | None) -> Path:
    """Configured path, resolved against the repository root when relative.

    Falls back to ``IDS_ZEEK_MODEL_PATH`` so a deployment can relocate the
    artefact without touching the code.
    """

    path = Path(configured or os.getenv("IDS_ZEEK_MODEL_PATH") or DEFAULT_MODEL_PATH)
    return path if path.is_absolute() else (ROOT / path)


class ZeekConnPredictor:
    def __init__(self, model_path: Path):
        bundle = joblib.load(model_path)
        if not isinstance(bundle, dict) or "model" not in bundle:
            raise ValueError(f"{model_path} is not a Zeek model bundle (missing 'model')")
        self.model = bundle["model"]
        self.path = Path(model_path)
        self.feature_names = tuple(bundle.get("features") or bundle.get("feature_names") or FEATURE_ORDER)
        if set(self.feature_names) != set(FEATURE_ORDER):
            raise ValueError(
                "model feature schema does not match src.realtime.features.FEATURE_ORDER "
                f"(model={len(self.feature_names)} features, code={len(FEATURE_ORDER)})"
            )
        self.schema_version = str(bundle.get("schema_version") or "zeek_conn_v1")
        self.classes = [str(c) for c in getattr(self.model, "classes_", bundle.get("classes", []))]
        self.threshold = bundle.get("threshold")
        self.metadata = bundle.get("metadata") or {}

    def predict_from_envelope(self, event: Mapping[str, Any]) -> dict[str, Any]:
        normalized = event.get("normalized") or {}
        row = NormalizedEvent(
            event_uid=str(event.get("uid") or event.get("event_id") or ""),
            ts=_num(event.get("ts")) or 0.0,
            log_type="conn",
            sensor=str(event.get("sensor_id") or ""),
            source_file=str(event.get("source_file") or ""),
            source_offset=_int(event.get("source_offset")) or 0,
            src_ip=event.get("src_ip"),
            dst_ip=event.get("dst_ip"),
            src_port=_int(event.get("src_port")),
            dst_port=_int(event.get("dst_port")),
            proto=event.get("proto") or normalized.get("proto"),
            service=event.get("service"),
            conn_state=normalized.get("conn_state") or event.get("conn_state"),
            duration=_num(normalized.get("duration")),
            orig_bytes=_int(normalized.get("orig_bytes")),
            resp_bytes=_int(normalized.get("resp_bytes")),
            orig_pkts=_int(normalized.get("orig_pkts")),
            resp_pkts=_int(normalized.get("resp_pkts")),
            orig_ip_bytes=_int(normalized.get("orig_ip_bytes")),
            resp_ip_bytes=_int(normalized.get("resp_ip_bytes")),
            raw=dict(event.get("raw") or {}),
        )
        features = features_from_zeek(row)
        if features is None:
            return {
                "label": UNCLASSIFIED,
                "status": "unscored",
                "reason": "event carries no connection-level volume data",
                "is_attack": False,
                "confidence": None,
                "probabilities": None,
                "schema_version": self.schema_version,
            }

        # The model was trained on a plain numpy matrix; feed the same shape or
        # sklearn warns about mismatched feature names.
        frame = np.array([[features[name] for name in self.feature_names]], dtype=float)
        pred = self.model.predict(frame)[0]
        out: dict[str, Any] = {
            "label": str(pred),
            "schema_version": self.schema_version,
            "confidence": None,
            "probabilities": None,
            "is_attack": str(pred).upper() not in {"BENIGN", "NORMAL"},
            "status": "scored",
            "reason": None,
        }
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(frame)[0]
            out["confidence"] = float(max(probs))
            out["probabilities"] = {str(c): float(p) for c, p in zip(self.classes, probs)}
        return out


_zeek_predictor: ZeekConnPredictor | None = None
_zeek_predictor_error: str | None = None
_zeek_predictor_attempted = False
_zeek_predictor_path: Path | None = None


def load_zeek_predictor(configured: Path | str | None = None) -> tuple[ZeekConnPredictor | None, str | None]:
    """Load once; return the predictor and the recorded failure reason, if any."""

    global _zeek_predictor, _zeek_predictor_error, _zeek_predictor_attempted, _zeek_predictor_path
    if _zeek_predictor is not None:
        return _zeek_predictor, None
    if _zeek_predictor_attempted:
        return None, _zeek_predictor_error

    _zeek_predictor_attempted = True
    _zeek_predictor_path = resolve_model_path(configured)
    if not _zeek_predictor_path.exists():
        _zeek_predictor_error = f"model file not found: {_zeek_predictor_path}"
        log.error("Zeek model unavailable: %s", _zeek_predictor_error)
        return None, _zeek_predictor_error
    try:
        _zeek_predictor = ZeekConnPredictor(_zeek_predictor_path)
        _zeek_predictor_error = None
        log.info(
            "Zeek model loaded: %s classes=%d features=%d",
            _zeek_predictor_path,
            len(_zeek_predictor.classes),
            len(_zeek_predictor.feature_names),
        )
    except Exception as exc:  # noqa: BLE001 - reported, never fatal
        _zeek_predictor = None
        _zeek_predictor_error = f"{type(exc).__name__}: {exc}"
        log.exception("Failed to load Zeek model at %s", _zeek_predictor_path)
    return _zeek_predictor, _zeek_predictor_error


def get_zeek_predictor(configured: Path | str | None = None) -> ZeekConnPredictor | None:
    predictor, _ = load_zeek_predictor(configured)
    return predictor


def zeek_model_state() -> dict[str, Any]:
    path = _zeek_predictor_path or resolve_model_path(None)
    predictor = _zeek_predictor
    return {
        "loaded": predictor is not None,
        "path": str(path),
        "exists": path.exists(),
        "error": _zeek_predictor_error,
        "schema_version": predictor.schema_version if predictor else None,
        "features": len(predictor.feature_names) if predictor else len(FEATURE_ORDER),
        "classes": predictor.classes if predictor else None,
        "threshold": predictor.threshold if predictor else None,
    }


def reset_zeek_predictor() -> None:
    """Drop the cached state (tests, and after publishing a new artefact)."""

    global _zeek_predictor, _zeek_predictor_error, _zeek_predictor_attempted, _zeek_predictor_path
    _zeek_predictor = None
    _zeek_predictor_error = None
    _zeek_predictor_attempted = False
    _zeek_predictor_path = None


def predict_zeek_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Score one normalised Zeek event envelope (never fabricates a label)."""

    log_type = str(event.get("log_type") or "unknown")
    if log_type != "conn":
        return {
            "label": UNCLASSIFIED,
            "status": "unscored",
            "reason": f"no Zeek ML model scores log_type={log_type}",
            "is_attack": False,
            "confidence": None,
            "probabilities": None,
            "schema_version": None,
        }
    predictor, error = load_zeek_predictor()
    if predictor is None:
        return {
            "label": UNCLASSIFIED,
            "status": "unscored",
            "reason": f"Zeek model unavailable: {error}",
            "is_attack": False,
            "confidence": None,
            "probabilities": None,
            "schema_version": None,
        }
    return predictor.predict_from_envelope(event)
