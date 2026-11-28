"""Model-loading contract for the deployed serving app.

The deployed service has to answer three questions correctly at all times:

* is the CICIDS artefact pair present, and does it actually score?
* is the Zeek model usable, independently of the CICIDS artefacts?
* does a missing artefact degrade the service instead of killing it?

These tests use real artefacts built on the fly (a fitted estimator plus the
preprocessor bundle contract) rather than mocks, so the same code path that runs
on Render is exercised here.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier

from src.serving.app import create_app
from src.serving.predictor import (
    Predictor,
    ArtifactError,
    load_predictor,
    predictor_state,
    reset_predictor,
)
from src.serving.zeek_predictor import reset_zeek_predictor

KEY = "test-api-key"
FEATURES = [f"feature_{i}" for i in range(6)]

CONN_RECORD = {
    "ts": 1700000000.0,
    "uid": "Ctest0001",
    "id.orig_h": "10.0.0.5",
    "id.orig_p": 41000,
    "id.resp_h": "10.0.0.9",
    "id.resp_p": 23,
    "proto": "tcp",
    "service": "-",
    "duration": 0.0,
    "orig_bytes": 0,
    "resp_bytes": 0,
    "conn_state": "S0",
    "orig_pkts": 1,
    "resp_pkts": 0,
    "orig_ip_bytes": 60,
    "resp_ip_bytes": 0,
}


class ColumnPassthrough:
    """Real transformer that keeps a DataFrame frame and the trained column order."""

    def __init__(self, columns: list[str]) -> None:
        self.columns = list(columns)

    def transform(self, frame: pd.DataFrame) -> pd.DataFrame:
        return frame[self.columns]


def build_artifacts(directory: Path, *, columns: list[str] | None = None) -> tuple[Path, Path]:
    columns = columns or FEATURES
    rows = []
    labels = []
    for index in range(12):
        attack = index % 2 == 0
        rows.append({column: (index + 1) * (2 if attack else 0.5) for column in columns})
        labels.append("DDoS" if attack else "BENIGN")
    frame = pd.DataFrame(rows)
    model = RandomForestClassifier(n_estimators=5, random_state=0).fit(frame, labels)

    model_path = directory / "best_model.joblib"
    preprocessor_path = directory / "preprocessor.joblib"
    joblib.dump(model, model_path)
    joblib.dump(
        {
            "preprocessor": ColumnPassthrough(columns),
            "feature_order": columns,
            "model_features": columns,
            "model_version": "test-2024",
            "metadata": {"version": "test-2024"},
        },
        preprocessor_path,
    )
    return model_path, preprocessor_path


@pytest.fixture(autouse=True)
def clean_state(monkeypatch, tmp_path):
    monkeypatch.setenv("IDS_DB_PATH", str(tmp_path / "ids.db"))
    monkeypatch.setenv("NDR_API_KEY", KEY)
    monkeypatch.delenv("IDS_API_KEY", raising=False)
    monkeypatch.delenv("IDS_ZEEK_MODEL_PATH", raising=False)
    reset_predictor()
    reset_zeek_predictor()
    yield
    reset_predictor()
    reset_zeek_predictor()


def point_at(monkeypatch, directory: Path) -> None:
    monkeypatch.setenv("IDS_MODEL_PATH", str(directory / "best_model.joblib"))
    monkeypatch.setenv("IDS_PREPROCESSOR_PATH", str(directory / "preprocessor.joblib"))


def test_missing_artifacts_report_the_file_and_a_remedy(monkeypatch, tmp_path):
    point_at(monkeypatch, tmp_path / "absent")

    predictor, error = load_predictor()

    assert predictor is None
    assert error is not None
    assert "best_model.joblib" in error
    state = predictor_state()
    assert state["loaded"] is False
    assert state["error_kind"] == "missing"
    assert state["artifacts"]["model"]["exists"] is False
    assert "fetch_models.py" in str(state["remediation"])
    assert state["version"] is None and state["features"] is None


def test_present_artifacts_load_and_score(monkeypatch, tmp_path):
    model_path, preprocessor_path = build_artifacts(tmp_path)
    point_at(monkeypatch, tmp_path)

    predictor = load_predictor()[0]
    assert predictor is not None
    result = predictor.predict({column: 1.0 for column in FEATURES})

    assert result["label"] in {"BENIGN", "DDoS"}
    assert result["confidence"] is not None and 0.0 <= result["confidence"] <= 1.0

    state = predictor_state()
    assert state["loaded"] is True
    assert state["error"] is None
    assert state["version"] == "test-2024"
    assert state["features"] == len(FEATURES)
    assert state["estimator"] == "RandomForestClassifier"
    assert state["artifacts"]["model"]["sha256"]
    assert state["loaded_at"]


def test_non_finite_and_missing_inputs_still_score(monkeypatch, tmp_path):
    """Real captures carry inf in the rate features of zero-duration flows."""

    build_artifacts(tmp_path)
    point_at(monkeypatch, tmp_path)
    predictor = load_predictor()[0]

    flow = {column: 0.5 for column in FEATURES}
    flow[FEATURES[0]] = float("inf")
    flow[FEATURES[1]] = float("-inf")
    flow[FEATURES[2]] = "not-a-number"
    flow[FEATURES[3]] = None
    del flow[FEATURES[4]]

    result = predictor.predict(flow)

    assert result["label"] in {"BENIGN", "DDoS"}
    assert result["confidence"] is not None and 0.0 <= result["confidence"] <= 1.0


def test_preprocessor_alone_missing_is_named(monkeypatch, tmp_path):
    model_path, _ = build_artifacts(tmp_path)
    point_at(monkeypatch, tmp_path)
    (tmp_path / "preprocessor.joblib").unlink()

    predictor, error = load_predictor()

    assert predictor is None
    assert "preprocessor.joblib" in error
    state = predictor_state()
    assert state["artifacts"]["model"]["exists"] is True
    assert state["artifacts"]["preprocessor"]["exists"] is False


def test_corrupt_preprocessor_is_not_reported_as_loaded(monkeypatch, tmp_path):
    build_artifacts(tmp_path)
    point_at(monkeypatch, tmp_path)
    (tmp_path / "preprocessor.joblib").write_text("not a joblib payload", encoding="utf-8")

    predictor, error = load_predictor()

    assert predictor is None
    assert "preprocessor" in error
    assert predictor_state()["error_kind"] == "invalid"


def test_schema_mismatch_between_model_and_preprocessor_fails_the_smoke_test(tmp_path):
    model_path, preprocessor_path = build_artifacts(tmp_path)
    wrong = [f"other_{i}" for i in range(len(FEATURES))]
    joblib.dump(
        {"preprocessor": ColumnPassthrough(wrong), "feature_order": wrong, "model_features": wrong},
        preprocessor_path,
    )

    with pytest.raises(ArtifactError) as excinfo:
        Predictor(model_path, preprocessor_path)

    assert excinfo.value.kind == "invalid"
    assert "contract" in excinfo.value.detail


def test_health_reports_both_models_independently(monkeypatch, tmp_path):
    point_at(monkeypatch, tmp_path / "absent")

    with TestClient(create_app()) as client:
        health = client.get("/api/v1/health")

    assert health.status_code == 200
    body = health.json()
    assert body["components"]["cicids_model"]["loaded"] is False
    assert body["components"]["zeek_model"]["loaded"] is True
    assert "cicids_model" in body["degraded_components"]
    assert body["models"]["cicids"]["version"] is None
    assert body["models"]["zeek"]["loaded"] is True
    assert body["models"]["zeek"]["features"] == 23


def test_zeek_scoring_survives_a_missing_cicids_model(monkeypatch, tmp_path):
    point_at(monkeypatch, tmp_path / "absent")

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v1/zeek/ingest/records",
            json={"records": [CONN_RECORD], "sensor_id": "test"},
            headers={"X-API-Key": KEY},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["inserted"] == 1
    assert body["scored"] == 1


def test_both_models_loaded_end_to_end(monkeypatch, tmp_path):
    build_artifacts(tmp_path)
    point_at(monkeypatch, tmp_path)

    with TestClient(create_app()) as client:
        health = client.get("/api/v1/health")
        scoring = client.post(
            "/api/v1/ingest/cic",
            json={"flows": [{column: 1.0 for column in FEATURES}]},
            headers={"X-API-Key": KEY},
        )

    assert health.status_code == 200
    body = health.json()
    assert body["components"]["cicids_model"]["loaded"] is True
    assert body["components"]["zeek_model"]["loaded"] is True
    assert body["degraded_components"] == []
    assert body["models"]["cicids"]["version"] == "test-2024"
    assert body["models"]["cicids"]["features"] == len(FEATURES)
    assert scoring.status_code == 200
    assert scoring.json()["predictions"][0]["label"] in {"BENIGN", "DDoS"}
