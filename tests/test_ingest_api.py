"""Remote sensor ingestion: auth, validation, scoring and live broadcast.

A hosted deployment cannot tail logs from the operator's network, so sensors push
records over HTTPS. These tests pin the security boundary (fail closed without a
key) and prove that pushed records travel the same pipeline as tailed ones.
"""

from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.realtime.config import PROJECT_ROOT, Settings

MODEL_PATH = PROJECT_ROOT / "models" / "zeek" / "zeek_model.joblib"

CONN_RECORD = {
    "ts": 1_700_000_000.0,
    "uid": "Cremote000001",
    "id.orig_h": "10.2.2.5",
    "id.orig_p": 41000,
    "id.resp_h": "10.2.2.9",
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


def _client(settings: Settings, **overrides):
    app = create_app(replace(settings, **overrides))
    return app, TestClient(app)


def test_ingest_disabled_without_api_key(settings: Settings) -> None:
    app, client = _client(settings)
    with client:
        response = client.post("/api/ingest/zeek", json={"records": [CONN_RECORD]})
        assert response.status_code == 503
        assert "NDR_API_KEY" in response.json()["detail"]
        assert app.state.ndr.store.count_events() == 0


def test_ingest_requires_matching_key(settings: Settings) -> None:
    _, client = _client(settings, api_key="s3cret")
    with client:
        assert client.post("/api/ingest/zeek", json={"records": [CONN_RECORD]}).status_code == 401
        assert (
            client.post(
                "/api/ingest/zeek",
                json={"records": [CONN_RECORD]},
                headers={"X-API-Key": "wrong"},
            ).status_code
            == 401
        )


def test_ingest_rejects_unknown_log_type(settings: Settings) -> None:
    _, client = _client(settings, api_key="s3cret")
    with client:
        response = client.post(
            "/api/ingest/zeek",
            json={"log_type": "../../etc/passwd", "records": [CONN_RECORD]},
            headers={"X-API-Key": "s3cret"},
        )
        assert response.status_code == 422


def test_ingest_rejects_batch_over_limit(settings: Settings) -> None:
    _, client = _client(settings, api_key="s3cret", remote_ingest_max_batch=1)
    with client:
        response = client.post(
            "/api/ingest/zeek",
            json={"records": [CONN_RECORD, {**CONN_RECORD, "uid": "Cremote000002"}]},
            headers={"X-API-Key": "s3cret"},
        )
        assert response.status_code == 413


def test_ingest_rejects_records_without_timestamp(settings: Settings) -> None:
    app, client = _client(settings, api_key="s3cret")
    with client:
        response = client.post(
            "/api/ingest/zeek",
            json={"records": [{"uid": "Cnots", "id.orig_h": "10.0.0.1"}]},
            headers={"X-API-Key": "s3cret"},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["rejected"] == 1
        assert body["inserted"] == 0
        assert body["results"][0]["status"] == "rejected"
        assert app.state.ndr.store.count_events() == 0


def test_ingest_dedupes_repeated_records(settings: Settings) -> None:
    app, client = _client(settings, api_key="s3cret")
    with client:
        first = client.post(
            "/api/ingest/zeek", json={"records": [CONN_RECORD]}, headers={"X-API-Key": "s3cret"}
        ).json()
        second = client.post(
            "/api/ingest/zeek", json={"records": [CONN_RECORD]}, headers={"X-API-Key": "s3cret"}
        ).json()

        assert first["inserted"] == 1
        assert second["inserted"] == 0
        assert second["duplicates"] == 1
        assert app.state.ndr.store.count_events() == 1


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="live model artifact not available")
def test_ingest_generates_real_prediction(settings: Settings) -> None:
    app, client = _client(settings, api_key="s3cret", model_path=MODEL_PATH)
    with client:
        response = client.post(
            "/api/ingest/zeek", json={"records": [CONN_RECORD]}, headers={"X-API-Key": "s3cret"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["inserted"] == 1
        assert body["predictions"] == 1

        result = body["results"][0]
        assert result["status"] == "inserted"
        assert isinstance(result["prediction"], str) and result["prediction"]

        event = client.get(f"/api/events/{result['event_id']}", headers={"X-API-Key": "s3cret"})
        assert event.status_code == 200
        payload = event.json()
        assert payload["prediction"] == result["prediction"]
        assert payload["model_name"] == "zeek-flow-classifier"
        assert payload["latency_ms"] is not None and payload["latency_ms"] >= 0
        assert payload["sensor"] == "test-sensor"

    assert app.state.ndr.model.is_loaded


def test_ingest_broadcasts_to_websocket(settings: Settings) -> None:
    app, client = _client(settings, api_key="s3cret")
    with client:
        with client.websocket_connect("/api/ws?api_key=s3cret") as ws:
            assert ws.receive_json()["type"] == "hello"

            client.post(
                "/api/ingest/zeek",
                json={"records": [CONN_RECORD]},
                headers={"X-API-Key": "s3cret"},
            )

            deadline = time.time() + 5
            while time.time() < deadline:
                message = ws.receive_json()
                if message["type"] == "event":
                    assert message["event"]["event_uid"].endswith("Cremote000001")
                    assert message["event"]["sensor"] == "test-sensor"
                    break
            else:  # pragma: no cover - defensive
                pytest.fail("pushed event was never broadcast")


def test_ingest_accepts_multiple_log_types(settings: Settings) -> None:
    app, client = _client(settings, api_key="s3cret")
    dns_record = {
        "ts": 1_700_000_100.0,
        "uid": "Cdns00000001",
        "id.orig_h": "10.2.2.5",
        "id.resp_h": "10.2.2.53",
        "proto": "udp",
        "query": "example.org",
        "qtype_name": "A",
        "rcode_name": "NOERROR",
    }
    with client:
        response = client.post(
            "/api/ingest/zeek",
            json={"log_type": "dns", "records": [dns_record]},
            headers={"X-API-Key": "s3cret"},
        )
        assert response.status_code == 200
        assert response.json()["inserted"] == 1
        assert app.state.ndr.store.count_events() == 1


def test_port_env_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PORT", "10000")
    settings = Settings.from_env()
    assert settings.api_port == 10000

    monkeypatch.delenv("PORT")
    monkeypatch.setenv("NDR_API_PORT", "9123")
    assert Settings.from_env().api_port == 9123
