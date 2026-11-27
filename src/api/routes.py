"""HTTP and WebSocket routes for the NDR platform."""

from __future__ import annotations

import asyncio
import csv
import hmac
import io
import time
from datetime import datetime, timezone
from typing import Any, Iterator

from fastapi import APIRouter, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse

router = APIRouter()

CSV_COLUMNS = [
    "id", "ts", "iso_time", "sensor", "log_type", "src_ip", "src_port", "dst_ip",
    "dst_port", "proto", "service", "conn_state", "duration", "orig_bytes",
    "resp_bytes", "orig_pkts", "resp_pkts", "prediction", "confidence",
    "severity", "is_malicious", "explanation", "latency_ms", "model_name",
    "model_version",
]


def _state(request: Request):
    return request.app.state.ndr


def _parse_ts(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError as error:
        raise HTTPException(status_code=400, detail=f"Invalid timestamp: {value}") from error


def _event_payload(event: dict[str, Any]) -> dict[str, Any]:
    payload = dict(event)
    payload["iso_time"] = datetime.fromtimestamp(event["ts"]).astimezone().isoformat(timespec="seconds")
    return payload


@router.get("/health")
def health(request: Request) -> dict[str, Any]:
    state = _state(request)
    return {
        "status": "ok",
        "version": request.app.version,
        "uptime_s": round(time.time() - state.started_at, 1),
        "ingestion_running": state.service.running if state.service else False,
        "ingest_enabled": state.settings.ingest_enabled,
        "sensor_id": state.settings.sensor_id,
        "sensor_mode": "replay" if state.store.replay_event_count() else state.settings.sensor_mode,
        "model_loaded": state.model.is_loaded,
        "database": state.store.db_status(),
        "database_path": str(state.settings.db_path),
    }


@router.get("/overview")
def overview(request: Request) -> dict[str, Any]:
    state = _state(request)
    data = state.store.overview(state.settings.metrics_window_s)
    data["model"] = {
        "name": state.model.name,
        "version": state.model.version,
        "loaded": state.model.is_loaded,
        "load_error": state.model.load_error,
        "threshold": state.model.metadata.get("threshold"),
        "trained_at": state.model.metadata.get("trained_at"),
        "training_datasets": state.model.metadata.get("training_datasets"),
    }
    sensor = state.service.status() if state.service else {}
    replay_records = state.store.replay_event_count()
    data["sensor"] = {
        "sensor_id": state.settings.sensor_id,
        "mode": "replay" if replay_records else state.settings.sensor_mode,
        "replay_records": replay_records,
        "ingestion_running": sensor.get("ingestion_running", False),
        "log_dir_exists": sensor.get("reader", {}).get("log_dir_exists", False),
        "log_file_count": sensor.get("reader", {}).get("log_file_count", 0),
        "seconds_since_event": sensor.get("seconds_since_event"),
        "last_error": sensor.get("last_error"),
    }
    data["websocket"] = state.hub.status()
    data["no_new_events"] = (
        data["seconds_since_last_event"] is None or data["seconds_since_last_event"] > 15
    )
    return data


@router.get("/events")
def events(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    search: str | None = None,
    proto: str | None = None,
    prediction: str | None = None,
    severity: str | None = None,
    start: str | None = None,
    end: str | None = None,
    malicious_only: bool = False,
) -> dict[str, Any]:
    state = _state(request)
    filters = dict(
        search=search, proto=proto, prediction=prediction, severity=severity,
        start=_parse_ts(start), end=_parse_ts(end), malicious_only=malicious_only,
    )
    rows = state.store.query_events(limit=limit, offset=offset, **filters)
    total = state.store.count_events(**filters)
    return {
        "items": [_event_payload(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/events/export.csv")
def export_events(
    request: Request,
    search: str | None = None,
    proto: str | None = None,
    prediction: str | None = None,
    severity: str | None = None,
    start: str | None = None,
    end: str | None = None,
    malicious_only: bool = False,
) -> StreamingResponse:
    state = _state(request)
    filters = dict(
        search=search, proto=proto, prediction=prediction, severity=severity,
        start=_parse_ts(start), end=_parse_ts(end), malicious_only=malicious_only,
    )

    def generate() -> Iterator[str]:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        yield buffer.getvalue()
        for event in state.store.iter_events(**filters):
            row = _event_payload(event)
            buffer.seek(0)
            buffer.truncate(0)
            writer.writerow(row)
            yield buffer.getvalue()

    filename = f"ndr_events_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/events/{event_id}")
def event_detail(request: Request, event_id: int) -> dict[str, Any]:
    state = _state(request)
    event = state.store.get_event(event_id)
    if event is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return _event_payload(event)


@router.get("/attacks")
def attacks(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: str | None = None,
    start: str | None = None,
    end: str | None = None,
) -> dict[str, Any]:
    state = _state(request)
    rows = state.store.query_attacks(
        limit=limit, offset=offset, severity=severity,
        start=_parse_ts(start), end=_parse_ts(end),
    )
    return {
        "items": [_event_payload(row) for row in rows],
        "total": state.store.count_attacks(
            severity=severity, start=_parse_ts(start), end=_parse_ts(end)
        ),
        "limit": limit,
        "offset": offset,
    }


@router.get("/analytics")
def analytics(
    request: Request,
    window: int = Query(3600, ge=10, le=86400),
) -> dict[str, Any]:
    state = _state(request)
    series_seconds = min(window, 900)
    return {
        "window_s": window,
        "generated_at": time.time(),
        "series": state.store.time_series(series_seconds),
        "attack_distribution": state.store.attack_distribution(window),
        "protocol_distribution": state.store.protocol_distribution(window),
        "severity_distribution": state.store.severity_distribution(window),
        "top_src_ips": state.store.top_ips("src_ip", 10, window),
        "top_dst_ips": state.store.top_ips("dst_ip", 10, window),
        "confidence_histogram": state.store.confidence_histogram(),
        "prediction_counts": state.store.prediction_counts(),
    }


@router.get("/model")
def model_info(request: Request) -> dict[str, Any]:
    return _state(request).model_service.info()


@router.get("/detections")
def detections(request: Request, window: int = Query(86400, ge=10, le=604800)) -> dict[str, Any]:
    state = _state(request)
    return {
        "window_s": window,
        "rules": state.store.alert_counts_by_rule(window),
        "detector_engine": (state.service.status()["detectors"] if state.service else {}),
    }


@router.get("/sensors")
def sensors(request: Request) -> dict[str, Any]:
    state = _state(request)
    service_status = state.service.status() if state.service else {
        "sensor_id": state.settings.sensor_id,
        "sensor_mode": state.settings.sensor_mode,
        "replay_records": 0,
        "ingestion_running": False,
        "ingest_enabled": state.settings.ingest_enabled,
        "poll_interval_s": state.settings.poll_interval_s,
        "counters": {},
        "last_poll_at": None,
        "last_event_at": None,
        "seconds_since_event": None,
        "last_error": None,
        "reader": {
            "log_dir": str(state.settings.zeek_log_dir),
            "log_dir_exists": state.settings.zeek_log_dir.exists(),
            "log_file_count": 0,
            "files_tracked": 0,
            "rotations": 0,
            "truncations": 0,
            "unparsed_lines": 0,
        },
        "detectors": {"rules": []},
    }
    ingestion_state = [
        {
            "source_file": path,
            "offset": record.get("offset"),
            "size": record.get("size"),
            "updated_at": record.get("updated_at"),
            "seconds_since_update": round(time.time() - record["updated_at"], 1)
            if record.get("updated_at")
            else None,
        }
        for path, record in state.store.get_ingestion_state().items()
    ]
    service_status["counters"] = {
        **service_status.get("counters", {}),
        "replay_records": state.store.replay_event_count(),
    }
    return {
        "sensor": service_status,
        "ingestion_state": ingestion_state,
        "database": state.store.db_status(),
        "api": {
            "status": "ok",
            "uptime_s": round(time.time() - state.started_at, 1),
            "version": request.app.version,
        },
        "websocket": state.hub.status(),
        "model": {
            "loaded": state.model.is_loaded,
            "name": state.model.name,
            "version": state.model.version,
            "load_error": state.model.load_error,
        },
        "processing_delay": state.store.processing_delay(),
        "dead_letters": state.store.dead_letter_count(),
        "server_time": time.time(),
    }


# --------------------------------------------------------------------------- #
# WebSocket live stream
# --------------------------------------------------------------------------- #
@router.websocket("/ws")
async def live_stream(websocket: WebSocket) -> None:
    state = websocket.app.state.ndr
    key = state.settings.api_key
    if key:
        provided = (
            websocket.query_params.get("api_key")
            or websocket.headers.get("x-api-key")
            or ""
        )
        if not hmac.compare_digest(provided, key):
            await websocket.close(code=1008)
            return
    manager = state.hub
    registered = manager.register()
    if registered is None:
        await websocket.close(code=1013)
        return
    client_id, queue = registered
    await websocket.accept()
    try:
        await websocket.send_json(
            {
                "type": "hello",
                "server_time": time.time(),
                "sensor": {
                    "sensor_id": state.settings.sensor_id,
                    "mode": state.settings.sensor_mode,
                },
                "model": {
                    "name": state.model.name,
                    "version": state.model.version,
                    "loaded": state.model.is_loaded,
                },
                "overview": state.store.overview(state.settings.metrics_window_s),
            }
        )
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=20.0)
            except asyncio.TimeoutError:
                message = {"type": "ping", "ts": time.time()}
            await websocket.send_json(message)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.unregister(client_id)
