"""FastAPI surface: REST payloads, CSV export and the WebSocket handshake."""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.realtime.config import Settings
from tests.conftest import event_row, prediction


@pytest.fixture()
def client(settings: Settings):
    app = create_app(settings)
    with TestClient(app) as test_client:
        yield test_client, app


def _seed(app) -> tuple[int, int]:
    store = app.state.ndr.store
    now = time.time()
    benign_id, _ = store.insert_event(event_row("C1", ts=now - 2, src_ip="10.0.0.5", dst_port=443))
    store.save_prediction(benign_id, prediction("BENIGN"))

    attack_id, _ = store.insert_event(
        event_row("C2", ts=now - 1, src_ip="203.0.113.9", dst_ip="10.0.0.10", dst_port=22, conn_state="REJ")
    )
    store.save_prediction(attack_id, prediction("BruteForce", severity="HIGH"))
    store.save_alert(
        attack_id,
        {
            "rule": "auth_brute_force",
            "category": "BruteForce",
            "severity": "HIGH",
            "confidence": 0.82,
            "explanation": "12 rejected logins to 10.0.0.10:22",
            "evidence": {"attempts": 12},
        },
    )
    return benign_id, attack_id


def test_health(client) -> None:
    test_client, _ = client
    payload = test_client.get("/api/health").json()

    assert payload["status"] == "ok"
    assert payload["ingest_enabled"] is False
    assert payload["database"]["integrity"] == "ok"


def test_overview_reports_real_counts(client) -> None:
    test_client, app = client
    _seed(app)

    payload = test_client.get("/api/overview").json()
    assert payload["total_events"] == 2
    assert payload["attacks"] == 1
    assert payload["benign"] == 1
    assert payload["total_alerts"] == 1
    assert payload["model"]["loaded"] is False
    assert payload["model"]["load_error"]


def test_events_list_and_detail(client) -> None:
    test_client, app = client
    benign_id, attack_id = _seed(app)

    listing = test_client.get("/api/events?limit=10").json()
    assert listing["total"] == 2
    assert listing["items"][0]["event_uid"] == "C2"  # newest first

    detail = test_client.get(f"/api/events/{attack_id}").json()
    assert detail["prediction"] == "BruteForce"
    assert detail["alerts"][0]["rule"] == "auth_brute_force"
    assert detail["raw"] == {"uid": "test"}

    assert test_client.get("/api/events/999999").status_code == 404


def test_event_filters(client) -> None:
    test_client, app = client
    _seed(app)

    assert test_client.get("/api/events?search=203.0.113.9").json()["total"] == 1
    assert test_client.get("/api/events?proto=tcp").json()["total"] == 2
    assert test_client.get("/api/events?prediction=BruteForce").json()["total"] == 1
    assert test_client.get("/api/events?severity=HIGH").json()["total"] == 1
    assert test_client.get("/api/events?malicious_only=true").json()["total"] == 1


def test_csv_export(client) -> None:
    test_client, app = client
    _seed(app)

    response = test_client.get("/api/events/export.csv?malicious_only=true")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    body = response.text.strip().splitlines()
    assert body[0].startswith("id,ts,iso_time")
    assert len(body) == 2


def test_attacks_endpoint(client) -> None:
    test_client, app = client
    _seed(app)

    payload = test_client.get("/api/attacks").json()
    assert payload["total"] == 1
    assert payload["items"][0]["prediction"] == "BruteForce"
    critical = test_client.get("/api/attacks?severity=CRITICAL").json()
    assert critical["total"] == 0
    assert critical["items"] == []


def test_analytics_payload_shape(client) -> None:
    test_client, app = client
    _seed(app)

    payload = test_client.get("/api/analytics?window=3600").json()
    assert payload["window_s"] == 3600
    assert isinstance(payload["series"], list)
    assert {item["label"] for item in payload["protocol_distribution"]} == {"tcp"}
    assert payload["prediction_counts"]["BENIGN"] == 1


def test_model_endpoint_distinguishes_both_models(client) -> None:
    test_client, _ = client
    payload = test_client.get("/api/model").json()

    assert payload["live_model"]["name"] == "zeek-flow-classifier"
    assert payload["live_model"]["kind"] == "realtime"
    assert payload["batch_model"]["kind"] == "batch"
    assert "runtime" in payload


def test_sensors_endpoint(client) -> None:
    test_client, _ = client
    payload = test_client.get("/api/sensors").json()

    assert payload["api"]["status"] == "ok"
    assert payload["database"]["integrity"] == "ok"
    assert payload["sensor"]["sensor_id"] == "test-sensor"
    assert payload["model"]["loaded"] is False


def test_websocket_hello_and_event_broadcast(client) -> None:
    test_client, app = client
    _, attack_id = _seed(app)
    event = app.state.ndr.store.get_event(attack_id)

    with test_client.websocket_connect("/api/ws") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello"

        app.state.ndr.hub.publish_threadsafe({"type": "event", "event": event, "ts": time.time()})

        for _ in range(10):
            message = ws.receive_json()
            if message["type"] == "event":
                assert message["event"]["id"] == attack_id
                break
        else:  # pragma: no cover - defensive
            pytest.fail("event broadcast never arrived")
