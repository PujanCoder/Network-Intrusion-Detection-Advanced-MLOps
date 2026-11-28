"""Regression tests for the deployed serving app (``src.serving``).

They pin the behaviour that was broken in production:

* every endpoint except ``/health`` returning 503 because no API key was set;
* the Zeek predictor pointing at an artefact that does not exist;
* a feature schema nobody trained, so no event could ever be scored;
* remotely pushed events being stored but never scored;
* missing CICIDS artefacts turning ``/health`` into a 500.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.realtime.features import FEATURE_ORDER
from src.serving.app import create_app
from src.serving.predictor import reset_predictor
from src.serving.zeek_predictor import load_zeek_predictor, reset_zeek_predictor, zeek_model_state

KEY = "test-api-key"

CONN_RECORD = {
    "ts": 1700000000.0,
    "uid": "Cscan0001",
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


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch, tmp_path):
    """Fresh DB, no key, CICIDS artefacts absent — the hosted deployment shape."""

    monkeypatch.setenv("IDS_DB_PATH", str(tmp_path / "ids.db"))
    monkeypatch.delenv("IDS_API_KEY", raising=False)
    monkeypatch.delenv("NDR_API_KEY", raising=False)
    monkeypatch.delenv("IDS_ZEEK_MODEL_PATH", raising=False)
    # The batch artefacts are DVC-tracked and absent from a git checkout; never
    # let a local `dvc pull` change what these tests observe.
    monkeypatch.setenv("IDS_MODEL_PATH", str(tmp_path / "no-cicids-model.joblib"))
    monkeypatch.setenv("IDS_PREPROCESSOR_PATH", str(tmp_path / "no-preprocessor.joblib"))
    reset_predictor()
    reset_zeek_predictor()
    yield
    reset_predictor()
    reset_zeek_predictor()


def client() -> TestClient:
    return TestClient(create_app())


def test_health_is_public_and_reports_real_component_state():
    with client() as c:
        response = c.get("/api/v1/health")
        assert response.status_code == 200
        body = response.json()

    assert body["app"] == "nids-serving"
    assert body["components"]["auth"] == {"configured": False, "source": None}
    # The tracked Zeek artefact must be usable in a clean checkout.
    assert body["components"]["zeek_model"]["loaded"] is True
    assert body["components"]["zeek_model"]["features"] == len(FEATURE_ORDER)
    # CICIDS artefacts are absent here and that must be reported, not hidden.
    assert body["components"]["cicids_model"]["loaded"] is False
    assert "cicids_model" in body["degraded_components"]
    assert body["status"] in {"ok", "degraded"}


def test_health_reports_the_deployed_commit(monkeypatch):
    monkeypatch.setenv("RENDER_GIT_COMMIT", "34ebf60deadbeef")
    monkeypatch.setenv("RENDER_GIT_BRANCH", "feature/realtime-ndr-platform")
    monkeypatch.delenv("GIT_COMMIT", raising=False)

    with client() as c:
        body = c.get("/api/v1/health").json()

    assert body["build"]["commit"] == "34ebf60deadbeef"
    assert body["build"]["branch"] == "feature/realtime-ndr-platform"


def test_data_endpoints_fail_closed_with_actionable_code():
    with client() as c:
        for path in ("/api/v1/zeek/status", "/api/v1/zeek/events", "/api/v1/zeek/detections"):
            response = c.get(path)
            assert response.status_code == 503, path
            detail = response.json()["detail"]
            assert detail["code"] == "auth_not_configured"
            assert any("IDS_API_KEY" in step for step in detail["remediation"])


def test_wrong_key_is_rejected_with_401(monkeypatch):
    monkeypatch.setenv("IDS_API_KEY", KEY)
    with client() as c:
        response = c.get("/api/v1/zeek/status", headers={"X-API-Key": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_api_key"


def test_ndr_api_key_alias_configures_the_app(monkeypatch):
    """One Render secret (NDR_API_KEY) must work for both apps."""

    monkeypatch.setenv("NDR_API_KEY", KEY)
    with client() as c:
        health = c.get("/api/v1/health").json()
        assert health["components"]["auth"] == {"configured": True, "source": "NDR_API_KEY"}
        status = c.get("/api/v1/zeek/status", headers={"X-API-Key": KEY})
    assert status.status_code == 200
    assert {"total", "detections_scored", "detections_attacks"} <= set(status.json()["counts"])


def test_zeek_model_loads_from_the_tracked_artifact():
    predictor, error = load_zeek_predictor()
    assert error is None
    assert predictor is not None
    assert tuple(predictor.feature_names) == FEATURE_ORDER
    assert zeek_model_state()["path"].endswith("models/zeek/zeek_model.joblib")


def test_conn_record_is_scored_and_persisted(monkeypatch):
    monkeypatch.setenv("IDS_API_KEY", KEY)
    headers = {"X-API-Key": KEY}
    with client() as c:
        response = c.post(
            "/api/v1/zeek/ingest/records",
            json={"records": [CONN_RECORD], "sensor_id": "sensor-1"},
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["inserted"] == 1
        assert response.json()["scored"] == 1

        detections = c.get("/api/v1/zeek/detections", headers=headers).json()["detections"]
        assert len(detections) == 1
        detection = detections[0]
        assert detection["status"] == "scored"
        assert detection["label"] in zeek_model_state()["classes"]
        assert 0.0 <= detection["confidence"] <= 1.0
        assert detection["sensor_id"] == "sensor-1"

        counts = c.get("/api/v1/zeek/status", headers=headers).json()["counts"]
        assert counts["total"] == 1
        assert counts["detections_scored"] == 1


def test_duplicate_push_is_not_rescored(monkeypatch):
    monkeypatch.setenv("IDS_API_KEY", KEY)
    headers = {"X-API-Key": KEY}
    with client() as c:
        c.post("/api/v1/zeek/ingest/records", json={"records": [CONN_RECORD]}, headers=headers)
        second = c.post("/api/v1/zeek/ingest/records", json={"records": [CONN_RECORD]}, headers=headers).json()
        counts = c.get("/api/v1/zeek/status", headers=headers).json()["counts"]

    assert second["duplicate"] == 1
    assert second["inserted"] == 0
    assert second["scored"] == 0
    assert counts["detections_total"] == 1


def test_non_conn_log_type_is_reported_unscored(monkeypatch):
    monkeypatch.setenv("IDS_API_KEY", KEY)
    dns_record = {
        "ts": 1700000001.0,
        "uid": "Cdns0001",
        "id.orig_h": "10.0.0.5",
        "id.orig_p": 53535,
        "id.resp_h": "1.1.1.1",
        "id.resp_p": 53,
        "proto": "udp",
        "query": "example.com",
        "qtype_name": "A",
    }
    with client() as c:
        body = c.post(
            "/api/v1/zeek/ingest/records",
            json={"records": [dns_record], "log_type": "dns"},
            headers={"X-API-Key": KEY},
        ).json()
        detections = c.get("/api/v1/zeek/detections", headers={"X-API-Key": KEY}).json()["detections"]

    assert body["unclassified"] == 1
    assert detections[0]["status"] == "unscored"
    assert detections[0]["label"] == "UNCLASSIFIED"
    assert "dns" in detections[0]["reason"]


def test_missing_zeek_model_does_not_crash_the_app(monkeypatch, tmp_path):
    monkeypatch.setenv("IDS_API_KEY", KEY)
    monkeypatch.setenv("IDS_ZEEK_MODEL_PATH", str(tmp_path / "absent.joblib"))
    reset_zeek_predictor()

    with client() as c:
        health = c.get("/api/v1/health")
        assert health.status_code == 200
        assert health.json()["components"]["zeek_model"]["loaded"] is False
        assert "not found" in health.json()["components"]["zeek_model"]["error"]

        response = c.post(
            "/api/v1/zeek/ingest/records",
            json={"records": [CONN_RECORD]},
            headers={"X-API-Key": KEY},
        )
        assert response.status_code == 200
        assert response.json()["inserted"] == 1
        assert response.json()["scored"] == 0
        assert response.json()["unclassified"] == 1


def test_missing_cicids_artifacts_return_actionable_503(monkeypatch):
    monkeypatch.setenv("IDS_API_KEY", KEY)
    with client() as c:
        response = c.post(
            "/api/v1/ingest/cic",
            json={"flows": [{"Destination Port": 80}]},
            headers={"X-API-Key": KEY},
        )

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["code"] == "cicids_model_unavailable"
    assert "dvc pull" in " ".join(detail["remediation"])


def test_ready_requires_a_working_scorer(monkeypatch, tmp_path):
    monkeypatch.setenv("IDS_API_KEY", KEY)
    monkeypatch.setenv("IDS_ZEEK_MODEL_PATH", str(tmp_path / "absent.joblib"))
    reset_zeek_predictor()

    with client() as c:
        response = c.get("/api/v1/ready")
        assert response.status_code == 503
        assert "no scoring model could be loaded" in response.json()["detail"]["reasons"]


def test_ready_when_zeek_model_is_available():
    with client() as c:
        response = c.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["ready"] is True


def test_dashboard_is_served():
    with client() as c:
        response = c.get("/")
    assert response.status_code == 200
    assert "api/v1/health" in response.text
    assert "Zeek Status" in response.text
