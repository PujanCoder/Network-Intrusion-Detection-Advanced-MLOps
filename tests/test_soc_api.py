"""Contract tests for the SOC dashboard API and its session authentication.

The fixtures write through the real stores (``ZeekStore``) and read through the
real HTTP app, so every assertion exercises production code: no mocked SQL, no
fabricated payloads.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.serving.app import create_app
from src.serving.security import SESSION_COOKIE

KEY = "soc-test-key"
HEADERS = {"X-API-Key": KEY}


def iso(offset_s: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=offset_s)).isoformat()


@pytest.fixture
def app_env(monkeypatch, tmp_path):
    monkeypatch.setenv("NDR_API_KEY", KEY)
    monkeypatch.setenv("IDS_DB_PATH", str(tmp_path / "ids.db"))
    monkeypatch.delenv("IDS_API_KEY", raising=False)
    monkeypatch.delenv("NDR_SESSION_SECRET", raising=False)
    monkeypatch.setenv("NDR_FRONTEND_DIST", str(tmp_path / "no-bundle"))
    return tmp_path


def connect(app_env):
    return TestClient(create_app())


def seed_event(app, *, sensor="sensor-a", ts=None, ingested=None, src="10.0.0.5",
               dst="10.0.0.9", dst_port=443, prediction=None):
    """Insert one event plus its detection through the real store code path."""

    stamp = ts or iso(-5)
    event = {
        "event_id": f"{sensor}-{stamp}-{dst_port}-{src}",
        "source": "zeek",
        "log_type": "conn",
        "ts": stamp,
        "ingested_at": ingested or stamp,
        "sensor_id": sensor,
        "uid": f"C{abs(hash(stamp)) % 10**8}",
        "src_ip": src,
        "src_port": 41000,
        "dst_ip": dst,
        "dst_port": dst_port,
        "proto": "tcp",
        "service": "ssl",
        "severity": None,
        "raw": {"ts": stamp, "id.orig_h": src, "id.resp_h": dst},
        "normalized": {
            "duration": 1.5,
            "orig_bytes": 900,
            "resp_bytes": 100,
            "conn_state": "SF",
            "orig_pkts": 6,
            "resp_pkts": 5,
        },
        "parse_status": "ok",
        "parse_errors": [],
        "source_file": f"remote:{sensor}:conn.log",
        "source_offset": 0,
        "source_inode": None,
    }
    assert app.state.zeek_store.insert_event(event) is True
    verdict = prediction or {
        "label": "BENIGN",
        "is_attack": False,
        "confidence": 0.41,
        "probabilities": {"BENIGN": 0.59, "Recon": 0.41},
        "status": "scored",
        "reason": None,
        "schema_version": "zeek_conn_v1",
    }
    det_id = app.state.zeek_store.insert_detection(event, verdict)
    return {"event": event, "detection_id": det_id}


def attack(label="Exploit", confidence=0.97, status="scored"):
    return {
        "label": label,
        "is_attack": True,
        "confidence": confidence,
        "probabilities": {label: confidence},
        "status": status,
        "reason": None,
        "schema_version": "zeek_conn_v1",
    }


def test_reads_require_authentication(app_env):
    with connect(app_env) as client:
        for path in (
            "/api/v1/metrics/overview",
            "/api/v1/metrics/live",
            "/api/v1/detections",
            "/api/v1/sensors",
            "/api/v1/models/status",
            "/api/v1/system/status",
            "/api/v1/detections/export",
        ):
            assert client.get(path).status_code == 401, path
            assert client.get(path, headers={"X-API-Key": "wrong"}).status_code == 401, path
            assert client.get(path, headers=HEADERS).status_code == 200, path


def test_not_configured_fails_closed(monkeypatch, tmp_path):
    monkeypatch.delenv("NDR_API_KEY", raising=False)
    monkeypatch.delenv("IDS_API_KEY", raising=False)
    monkeypatch.setenv("IDS_DB_PATH", str(tmp_path / "ids.db"))
    monkeypatch.setenv("NDR_FRONTEND_DIST", str(tmp_path / "none"))
    with TestClient(create_app()) as client:
        response = client.get("/api/v1/detections")
        session = client.get("/api/v1/session").json()
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "auth_not_configured"
    assert session["configured"] is False
    assert session["authenticated"] is False


def test_overview_counts_come_from_the_database(app_env):
    with connect(app_env) as client:
        seed_event(app=client.app, src="10.0.0.5", prediction=attack())
        seed_event(app=client.app, src="10.0.0.6", dst_port=53)
        seed_event(
            app=client.app,
            src="10.0.0.7",
            dst_port=22,
            prediction={
                "label": "UNCLASSIFIED",
                "is_attack": False,
                "confidence": None,
                "probabilities": None,
                "status": "unclassified",
                "reason": "no compatible feature vector",
                "schema_version": "zeek_conn_v1",
            },
        )
        body = client.get("/api/v1/metrics/overview", headers=HEADERS).json()

    totals = body["totals"]
    assert totals["events"] == 3
    assert totals["detections"] == 3
    assert totals["attacks"] == 1
    assert totals["benign"] == 1
    assert totals["scored"] == 2
    assert totals["unclassified"] == 1
    assert totals["detection_rate"] == 0.5  # 1 attack / 2 scored
    assert totals["by_source"] == {"zeek": 3}
    assert body["activity"]["no_new_events"] is False
    assert body["sensors"]["online"] == 1
    assert body["severity_policy"]["source"] == "rule:confidence-band-v1"

    labels = {item["label"]: item["count"] for item in body["distributions"]["labels"]}
    assert labels == {"Exploit": 1, "BENIGN": 1, "UNCLASSIFIED": 1}
    severities = {item["label"]: item["count"] for item in body["distributions"]["severities"]}
    assert severities == {"CRITICAL": 1, "INFO": 1, "UNKNOWN": 1}
    assert any(point["attacks"] == 1 for point in body["series"])
    assert len(body["recent"]) == 3
    assert body["recent"][0]["severity_source"] == "rule:confidence-band-v1"


def test_empty_database_reports_zero_and_no_events(app_env):
    with connect(app_env) as client:
        body = client.get("/api/v1/metrics/overview", headers=HEADERS).json()
    assert body["totals"]["events"] == 0
    assert body["totals"]["detection_rate"] is None
    assert body["activity"]["no_new_events"] is True
    assert body["activity"]["message"] == "No new network events received."
    assert body["sensors"]["total"] == 0
    assert all(point["predictions"] == 0 for point in body["series"])
    assert body["recent"] == []


def test_severity_bands_follow_the_documented_rule():
    from src.serving.soc_store import severity_of

    assert severity_of(True, 0.95) == "CRITICAL"
    assert severity_of(True, 0.80) == "HIGH"
    assert severity_of(True, 0.60) == "MEDIUM"
    assert severity_of(True, 0.10) == "LOW"
    assert severity_of(True, None) == "LOW"
    assert severity_of(False, 0.99) == "INFO"
    assert severity_of(False, None, scored=False) == "UNKNOWN"


def test_detections_support_filters_and_pagination(app_env):
    with connect(app_env) as client:
        for index in range(12):
            label, is_attack = ("Recon", True) if index % 2 else ("BENIGN", False)
            seed_event(
                app=client.app,
                src=f"10.1.0.{index}",
                dst_port=1000 + index,
                prediction={
                    "label": label,
                    "is_attack": is_attack,
                    "confidence": 0.5 + index / 100,
                    "probabilities": {label: 0.5},
                    "status": "scored",
                    "reason": None,
                    "schema_version": "zeek_conn_v1",
                },
            )
        first = client.get("/api/v1/detections?limit=5&offset=0", headers=HEADERS).json()
        second = client.get("/api/v1/detections?limit=5&offset=5", headers=HEADERS).json()
        attacks = client.get("/api/v1/detections?only_attacks=true", headers=HEADERS).json()
        searched = client.get("/api/v1/detections?q=10.1.0.3", headers=HEADERS).json()
        by_severity = client.get("/api/v1/detections?severity=MEDIUM", headers=HEADERS).json()

    assert first["total"] == 12
    assert len(first["items"]) == 5
    assert first["has_more"] is True
    assert {row["id"] for row in first["items"]}.isdisjoint({row["id"] for row in second["items"]})
    assert attacks["total"] == 6
    assert all(row["is_attack"] for row in attacks["items"])
    assert searched["total"] == 1
    assert searched["items"][0]["src_ip"] == "10.1.0.3"
    # MEDIUM applies to attacks only: even indices are BENIGN and stay INFO.
    assert by_severity["total"] == 6
    assert all(row["severity"] == "MEDIUM" and row["is_attack"] for row in by_severity["items"])
    stamps = [row["ts"] for row in first["items"]]
    assert stamps == sorted(stamps, reverse=True)


def test_query_validation_rejects_bad_input(app_env):
    with connect(app_env) as client:
        assert client.get("/api/v1/detections?limit=0", headers=HEADERS).status_code == 422
        assert client.get("/api/v1/detections?limit=500", headers=HEADERS).status_code == 422
        assert client.get("/api/v1/detections?severity=catastrophic", headers=HEADERS).status_code == 422
        assert client.get("/api/v1/detections?start=not-a-date", headers=HEADERS).status_code == 422
        ordered = "/api/v1/detections?start=2026-01-02T00:00:00Z&end=2026-01-01T00:00:00Z"
        assert client.get(ordered, headers=HEADERS).status_code == 422


def test_detection_detail_and_missing_ids(app_env):
    with connect(app_env) as client:
        seeded = seed_event(app=client.app, src="10.9.9.9")
        good = client.get(f"/api/v1/detections/zeek:{seeded['detection_id']}", headers=HEADERS)
        missing = client.get("/api/v1/detections/zeek:999999", headers=HEADERS)
        malformed = client.get("/api/v1/detections/not-a-detection", headers=HEADERS)

    assert good.status_code == 200
    body = good.json()
    assert body["id"] == f"zeek:{seeded['detection_id']}"
    assert body["src_ip"] == "10.9.9.9"
    assert body["conn_state"] == "SF"
    assert body["raw"]["id.orig_h"] == "10.9.9.9"
    assert body["envelope"]["event_id"] == seeded["event"]["event_id"]
    assert body["probabilities"]["BENIGN"] == 0.59
    assert body["severity"] == "INFO"
    assert missing.status_code == 404
    assert malformed.status_code == 422


def test_export_streams_filtered_csv(app_env):
    with connect(app_env) as client:
        seed_event(app=client.app, src="10.2.2.2")
        seed_event(app=client.app, src="10.2.2.3")
        response = client.get("/api/v1/detections/export?q=10.2.2.2", headers=HEADERS)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment; filename=" in response.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(response.text)))
    assert len(rows) == 1
    assert rows[0]["detection_id"].startswith("zeek:")
    assert rows[0]["src_ip"] == "10.2.2.2"
    assert rows[0]["severity_source"] == "rule:confidence-band-v1"
    assert rows[0]["model_schema"] == "zeek_conn_v1"


def test_sensor_liveness_uses_timestamps_not_row_existence(app_env):
    with connect(app_env) as client:
        seed_event(app=client.app, sensor="recent-sensor", ingested=iso(-10))
        seed_event(app=client.app, sensor="silent-sensor", ingested=iso(-4 * 3600))
        body = client.get("/api/v1/sensors", headers=HEADERS).json()

    by_id = {row["sensor_id"]: row for row in body["sensors"]}
    assert by_id["recent-sensor"]["status"] == "online"
    assert by_id["silent-sensor"]["status"] == "offline"
    assert "silent for" in by_id["silent-sensor"]["status_reason"]
    assert body["summary"]["online"] == 1
    assert body["summary"]["offline"] == 1
    assert body["summary"]["events"] == 2
    assert body["expected"]["mode"] == "remote"
    assert by_id["recent-sensor"]["events"] == 1


def test_models_status_separates_the_two_models(app_env):
    with connect(app_env) as client:
        seed_event(app=client.app)
        body = client.get("/api/v1/models/status", headers=HEADERS).json()

    cicids, zeek = body["models"]["cicids"], body["models"]["zeek"]
    assert cicids["experimental"] is False
    assert zeek["experimental"] is True
    assert any("synthetic" in note.lower() for note in zeek["notes"])
    assert zeek["runtime"]["predictions"] == 1
    assert cicids["runtime"]["predictions"] == 0
    assert zeek["latency"]["available"] is False
    assert "not persist" in zeek["latency"]["reason"]
    assert zeek["classes"]
    assert cicids["schema"]["features"] == 78


def test_system_status_reports_build_database_and_websocket(app_env, monkeypatch):
    monkeypatch.setenv("RENDER_GIT_COMMIT", "abc123def456")
    monkeypatch.setenv("RENDER_GIT_BRANCH", "feature/realtime-ndr-platform")
    with TestClient(create_app()) as client:
        body = client.get("/api/v1/system/status", headers=HEADERS).json()

    assert body["build"]["commit"] == "abc123def456"
    assert body["build"]["branch"] == "feature/realtime-ndr-platform"
    assert body["status"] in {"ok", "degraded"}
    assert body["database"]["integrity"] == "ok"
    assert body["websocket"]["available"] is True
    assert body["auth"]["request_authenticated_by"] == "api_key"
    assert body["endpoints"]["alerts"] == "/ws/alerts"
    assert set(body["components"]) >= {"cicids_model", "zeek_model", "database", "auth", "zeek_ingestion"}


def test_login_sets_httponly_cookie_and_grants_read_access(app_env):
    with connect(app_env) as client:
        response = client.post("/api/v1/session", json={"api_key": KEY})
        assert response.status_code == 200
        assert response.json()["authenticated"] is True
        cookie_header = response.headers["set-cookie"]
        assert f"{SESSION_COOKIE}=" in cookie_header
        assert "HttpOnly" in cookie_header
        assert "samesite=lax" in cookie_header.lower()
        assert "Path=/" in cookie_header

        assert client.get("/api/v1/detections").status_code == 200
        state = client.get("/api/v1/session").json()
        assert state["authenticated"] is True
        assert state["method"] == "session"
        assert state["expires_at"] > 0

        client.delete("/api/v1/session")
        assert client.get("/api/v1/detections").status_code == 401


def test_login_rejects_a_wrong_key(app_env):
    with connect(app_env) as client:
        response = client.post("/api/v1/session", json={"api_key": "nope"})
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_api_key"
    assert SESSION_COOKIE not in response.headers.get("set-cookie", "")


def test_tampered_session_cookie_is_rejected(app_env):
    with connect(app_env) as client:
        client.post("/api/v1/session", json={"api_key": KEY})
        token = client.cookies.get(SESSION_COOKIE)
        expires, _, mac = token.partition(".")
        client.cookies.set(SESSION_COOKIE, f"{expires}.{'0' * len(mac)}")
        response = client.get("/api/v1/detections")
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "invalid_session"


def test_expired_session_is_rejected(app_env, monkeypatch):
    from src.serving import security

    class Clock:
        def __init__(self, now):
            self.now = now

        def time(self):
            return self.now

    monkeypatch.setattr(security, "time", Clock(1_000_000))
    with connect(app_env) as client:
        token, _ = security.issue_session(client.app.state.settings, ttl_s=60)
        client.cookies.set(SESSION_COOKIE, token)
        monkeypatch.setattr(security, "time", Clock(1_000_500))
        response = client.get("/api/v1/detections")
    assert response.status_code == 401


def test_cookie_is_not_accepted_for_writes(app_env):
    """A cookie authenticates reads only, so a cross-site POST cannot push records."""

    with connect(app_env) as client:
        client.post("/api/v1/session", json={"api_key": KEY})
        response = client.post("/api/v1/zeek/ingest/records", json={"records": [{"ts": 1}]})
    assert response.status_code == 401


def test_login_is_throttled_after_repeated_failures(app_env):
    from src.serving.routes import auth_routes

    auth_routes.reset_throttle()
    try:
        with connect(app_env) as client:
            codes = [client.post("/api/v1/session", json={"api_key": "wrong"}).status_code for _ in range(11)]
    finally:
        auth_routes.reset_throttle()
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


def test_websocket_requires_authentication(app_env):
    from starlette.websockets import WebSocketDisconnect

    with connect(app_env) as client:
        with client.websocket_connect("/ws/alerts") as socket:
            with pytest.raises(WebSocketDisconnect) as denied:
                socket.receive_json()
        assert denied.value.code == 1008

        with client.websocket_connect(f"/ws/alerts?api_key={KEY}") as socket:
            hello = socket.receive_json()
    assert hello["type"] == "hello"
    assert hello["authenticated_by"] == "api_key"
    assert "totals" in hello["overview"]


def test_websocket_accepts_the_session_cookie(app_env):
    with connect(app_env) as client:
        client.post("/api/v1/session", json={"api_key": KEY})
        with client.websocket_connect("/ws/alerts") as socket:
            hello = socket.receive_json()
    assert hello["type"] == "hello"
    assert hello["authenticated_by"] == "session"


def test_broadcast_detection_pushes_to_registered_clients(app_env):
    import asyncio

    class Recorder:
        def __init__(self):
            self.messages = []

        async def send_json(self, payload):
            self.messages.append(payload)

    async def scenario():
        with connect(app_env) as client:
            from src.serving.soc import broadcast_detection

            hub = client.app.state.hub
            hub.bind_loop(asyncio.get_running_loop())
            recorder = Recorder()
            assert await hub.register(recorder) is True
            seeded = seed_event(app=client.app, src="10.3.3.3")
            broadcast_detection(client.app.state, "zeek", seeded["detection_id"])
            await asyncio.sleep(0.2)
            return recorder.messages

    messages = asyncio.run(scenario())
    assert len(messages) == 1
    assert messages[0]["type"] == "event"
    assert messages[0]["event"]["src_ip"] == "10.3.3.3"


def test_dashboard_bundle_is_served_when_present(monkeypatch, tmp_path):
    index = Path(__file__).resolve().parents[1] / "frontend" / "dist" / "index.html"
    if not index.is_file():
        pytest.skip("frontend bundle not built in this checkout")

    monkeypatch.setenv("NDR_API_KEY", KEY)
    monkeypatch.setenv("IDS_DB_PATH", str(tmp_path / "ids.db"))
    monkeypatch.delenv("NDR_FRONTEND_DIST", raising=False)
    with TestClient(create_app()) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert '<div id="root">' in page.text
        asset = next(
            (part for part in page.text.split('"') if part.startswith("/assets/") and part.endswith(".js")),
            None,
        )
        assert asset is not None
        assert client.get(asset).status_code == 200


def test_legacy_status_page_is_used_without_a_bundle(app_env):
    with connect(app_env) as client:
        page = client.get("/")
    assert page.status_code == 200
    assert "api/v1/health" in page.text
