"""Inference wrapper around the Zeek-compatible flow classifier.

The wrapper is intentionally thin: all feature construction lives in
``src.realtime.features`` so the exact same code path is used for training and
serving. It measures real per-prediction latency and degrades to a recorded
error (never a crash, never a fabricated label) when the model is unavailable.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from src.realtime.features import FEATURE_ORDER, vector

BENIGN = "BENIGN"

SEVERITY_BY_CATEGORY = {
    "BENIGN": "INFO",
    "DoS": "CRITICAL",
    "DDoS": "CRITICAL",
    "Backdoor": "CRITICAL",
    "Worm": "CRITICAL",
    "Exploit": "HIGH",
    "BruteForce": "HIGH",
    "CommandAndControl": "CRITICAL",
    "Exfiltration": "CRITICAL",
    "DnsTunneling": "HIGH",
    "WebAttack": "HIGH",
    "Recon": "MEDIUM",
    "PortScan": "MEDIUM",
    "Analysis": "MEDIUM",
    "Fuzz": "MEDIUM",
    "Other": "MEDIUM",
}

_EXPLAIN_FEATURES = (
    "orig_bytes",
    "resp_bytes",
    "duration_s",
    "dst_port_class",
    "flow_packets_per_s",
    "conn_state_code",
)


@dataclass
class ModelPrediction:
    label: str
    is_malicious: bool
    confidence: float
    malicious_score: float
    threshold: float
    severity: str
    explanation: str
    latency_ms: float
    model_name: str
    model_version: str
    created_at: float

    def to_store_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "label": self.label,
            "is_malicious": self.is_malicious,
            "confidence": self.confidence,
            "malicious_score": self.malicious_score,
            "threshold": self.threshold,
            "severity": self.severity,
            "explanation": self.explanation,
            "latency_ms": self.latency_ms,
            "created_at": self.created_at,
        }


class ZeekModel:
    """Loads a trained artifact and scores flow feature dictionaries."""

    def __init__(self, artifact_path: str | Path) -> None:
        self.artifact_path = Path(artifact_path)
        self._model: Any = None
        self._classes: list[str] = []
        self._threshold: float = 0.5
        self.metadata: dict[str, Any] = {}
        self.load_error: str | None = None

    # ------------------------------------------------------------------ #
    def load(self) -> bool:
        if not self.artifact_path.exists():
            self.load_error = f"model artifact not found: {self.artifact_path}"
            return False
        try:
            artifact = joblib.load(self.artifact_path)
        except Exception as error:  # corrupted artifact must not kill the API
            self.load_error = f"could not load model: {error}"
            return False

        self._model = artifact["model"]
        self._classes = list(artifact.get("classes") or getattr(self._model, "classes_", []))
        self._threshold = float(artifact.get("threshold", 0.5))
        self.metadata = artifact.get("metadata", {})
        expected = artifact.get("features") or FEATURE_ORDER
        if list(expected) != list(FEATURE_ORDER):
            self.load_error = "feature schema mismatch between artifact and code"
            self._model = None
            return False
        self.load_error = None
        return True

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def name(self) -> str:
        return self.metadata.get("model_name", "zeek-flow-classifier")

    @property
    def version(self) -> str:
        return self.metadata.get("model_version", "unknown")

    # ------------------------------------------------------------------ #
    def predict(self, features: dict[str, Any]) -> ModelPrediction | None:
        if not self.is_loaded:
            return None
        row = np.asarray([vector(features)], dtype=float)
        started = time.perf_counter()
        try:
            probabilities = self._model.predict_proba(row)[0]
        except Exception as error:
            self.load_error = f"inference failed: {error}"
            return None
        latency_ms = (time.perf_counter() - started) * 1000.0

        classes = self._classes or list(self._model.classes_)
        by_class = {str(label): float(prob) for label, prob in zip(classes, probabilities)}
        malicious_score = 1.0 - by_class.get(BENIGN, 0.0)
        is_malicious = malicious_score >= self._threshold

        if is_malicious:
            candidates = {k: v for k, v in by_class.items() if k != BENIGN}
            label = max(candidates, key=candidates.get) if candidates else "Other"
            confidence = float(by_class[label])
        else:
            label = BENIGN
            confidence = float(by_class.get(BENIGN, 1.0 - malicious_score))

        severity = self._severity(label, confidence)
        explanation = self._explain(label, confidence, malicious_score, features)

        return ModelPrediction(
            label=label,
            is_malicious=is_malicious,
            confidence=round(confidence, 4),
            malicious_score=round(malicious_score, 4),
            threshold=self._threshold,
            severity=severity,
            explanation=explanation,
            latency_ms=round(latency_ms, 3),
            model_name=self.name,
            model_version=self.version,
            created_at=time.time(),
        )

    # ------------------------------------------------------------------ #
    @staticmethod
    def _severity(label: str, confidence: float) -> str:
        if label == BENIGN:
            return "INFO"
        base = SEVERITY_BY_CATEGORY.get(label, "MEDIUM")
        if base == "CRITICAL" and confidence < 0.6:
            return "HIGH"
        if base == "HIGH" and confidence < 0.6:
            return "MEDIUM"
        return base

    def _explain(
        self, label: str, confidence: float, malicious_score: float, features: dict[str, Any]
    ) -> str:
        if label == BENIGN:
            verdict = "benign flow"
        else:
            verdict = f"{label} pattern"
        parts = [
            f"{verdict} (confidence {confidence:.0%}, malicious score {malicious_score:.2f} "
            f"vs threshold {self._threshold:.2f})"
        ]
        details = []
        for name in _EXPLAIN_FEATURES:
            value = features.get(name)
            if value is None:
                continue
            if name in {"orig_bytes", "resp_bytes"}:
                details.append(f"{name}={value:.0f}B")
            elif name == "flow_packets_per_s":
                details.append(f"pkts/s={value:.1f}")
            elif name == "duration_s":
                details.append(f"duration={value:.3f}s")
            elif name == "dst_port_class":
                details.append(f"port class={value:.0f}")
            else:
                details.append(f"{name}={value:.0f}")
        if details:
            parts.append("flow: " + ", ".join(details))
        top = self.metadata.get("top_features") or []
        if top:
            names = ", ".join(item["feature"] for item in top[:3])
            parts.append(f"globally most influential features: {names}")
        return "; ".join(parts)

    # ------------------------------------------------------------------ #
    def info(self) -> dict[str, Any]:
        metadata = dict(self.metadata)
        metadata.update(
            {
                "loaded": self.is_loaded,
                "load_error": self.load_error,
                "artifact_path": str(self.artifact_path),
                "feature_schema": list(FEATURE_ORDER),
                "threshold": self._threshold,
                "classes": self._classes,
            }
        )
        if not metadata.get("model_name"):
            metadata["model_name"] = "zeek-flow-classifier"
        return metadata


def load_model_metadata(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
