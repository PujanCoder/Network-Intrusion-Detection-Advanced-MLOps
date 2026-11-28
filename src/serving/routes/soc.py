"""SOC dashboard API: metrics, detections, sensors, models, system, alerts.

Every route here is a read except the WebSocket handshake, and every route
requires either ``X-API-Key`` (machines) or the dashboard session cookie
(browsers). All numbers are computed from SQLite; nothing is cached or seeded.
"""

from __future__ import annotations

import csv
import io
import logging
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Literal

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import StreamingResponse

from src.serving.security import SESSION_COOKIE, require_access, verify_session
from src.serving.soc import overview_payload, sensor_payload, system_payload
from src.serving.soc_store import SEVERITY_POLICY, DetectionFilters, SocStore

router = APIRouter(prefix="/api/v1")
# The alert stream lives at /ws/alerts, outside the /api/v1 namespace so it keeps
# the conventional path the dashboard and the docs reference.
ws_router = APIRouter()

log = logging.getLogger(__name__)

Source = Literal["zeek", "cicids"]
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SortOrder = Literal["ts_desc", "ts_asc"]
DetectionStatus = Literal["scored", "unclassified"]

CSV_COLUMNS = [
    "detection_id", "source", "ts", "sensor_id", "log_type", "src_ip", "src_port",
    "dst_ip", "dst_port", "proto", "service", "conn_state", "duration",
    "orig_bytes", "resp_bytes", "label", "is_attack", "confidence", "severity",
    "severity_source", "status", "model_name", "model_schema", "explanation",
]


def _store(request: Request) -> SocStore:
    return request.app.state.soc_store


def _auth(request: Request, x_api_key: str | None) -> str:
    return require_access(request.app.state.settings, x_api_key, request)


def parse_timestamp(value: str | None, name: str) -> str | None:
    """Accept ISO-8601 or epoch seconds; return UTC ISO-8601 for the SQL layer."""

    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        epoch = float(text)
    except ValueError:
        pass
    else:
        return datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=f"{name} must be ISO-8601 or epoch seconds") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _filters(
    *,
    source: Source | None,
    label: str | None,
    severity: Severity | None,
    status: DetectionStatus | None,
    sensor_id: str | None,
    model: Source | None,
    q: str | None,
    start: str | None,
    end: str | None,
    only_attacks: bool,
) -> DetectionFilters:
    start_iso = parse_timestamp(start, "start")
    end_iso = parse_timestamp(end, "end")
    if start_iso and end_iso and start_iso > end_iso:
        raise HTTPException(status_code=422, detail="start must be before end")
    sources = (source,) if source else ("zeek", "cicids")
    return DetectionFilters(
        sources=sources,
        label=label,
        severity=severity,
        status=status,
        sensor_id=sensor_id,
        model=model,
        search=q,
        start=start_iso,
        end=end_iso,
        only_attacks=only_attacks,
    )


@router.get("/metrics/overview")
def metrics_overview(
    request: Request,
    window: int = Query(default=3600, ge=60, le=86400),
    x_api_key: str | None = Header(default=None),
):
    _auth(request, x_api_key)
    return overview_payload(request.app.state, window_s=window)


@router.get("/metrics/live")
def metrics_live(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    source: Source | None = Query(default=None),
    x_api_key: str | None = Header(default=None),
):
    """Recent detections for the live table, with an explicit freshness verdict."""

    _auth(request, x_api_key)
    store = _store(request)
    filters = DetectionFilters(sources=(source,) if source else ("zeek", "cicids"))
    records, total = store.list_detections(filters, limit=limit)
    totals = store.totals()
    now = time.time()
    last = totals["last_event_ts"]
    seconds = None
    if last:
        try:
            parsed = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
            seconds = round(max(0.0, now - parsed.timestamp()), 1)
        except ValueError:
            seconds = None
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "server_time": now,
        "records": records,
        "total": total,
        "last_event_ts": last,
        "seconds_since_event": seconds,
        "no_new_events": totals["events"] == 0,
        "activity_message": "No new network events received." if totals["events"] == 0 else None,
        "websocket": request.app.state.hub.status(),
    }


@router.get("/detections")
def list_detections(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=1_000_000),
    source: Source | None = Query(default=None),
    label: str | None = Query(default=None, max_length=64),
    severity: Severity | None = Query(default=None),
    status: DetectionStatus | None = Query(default=None),
    sensor_id: str | None = Query(default=None, max_length=64),
    model: Source | None = Query(default=None),
    q: str | None = Query(default=None, max_length=128),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    only_attacks: bool = Query(default=False),
    sort: SortOrder = Query(default="ts_desc"),
    x_api_key: str | None = Header(default=None),
):
    _auth(request, x_api_key)
    filters = _filters(
        source=source, label=label, severity=severity, status=status, sensor_id=sensor_id,
        model=model, q=q, start=start, end=end, only_attacks=only_attacks,
    )
    items, total = _store(request).list_detections(filters, limit=limit, offset=offset, sort=sort)
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < total,
        "sort": sort,
        "severity_policy": SEVERITY_POLICY,
        "filters": {
            "source": source, "label": label, "severity": severity, "status": status,
            "sensor_id": sensor_id, "model": model, "q": q, "start": start, "end": end,
            "only_attacks": only_attacks,
        },
    }


@router.get("/detections/export")
def export_detections(
    request: Request,
    source: Source | None = Query(default=None),
    label: str | None = Query(default=None, max_length=64),
    severity: Severity | None = Query(default=None),
    status: DetectionStatus | None = Query(default=None),
    sensor_id: str | None = Query(default=None, max_length=64),
    model: Source | None = Query(default=None),
    q: str | None = Query(default=None, max_length=128),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    only_attacks: bool = Query(default=False),
    sort: SortOrder = Query(default="ts_desc"),
    x_api_key: str | None = Header(default=None),
):
    _auth(request, x_api_key)
    filters = _filters(
        source=source, label=label, severity=severity, status=status, sensor_id=sensor_id,
        model=model, q=q, start=start, end=end, only_attacks=only_attacks,
    )
    store = _store(request)

    def generate() -> Iterator[str]:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        yield buffer.getvalue()
        for record in store.iter_detections(filters, sort=sort):
            row = {
                **record,
                "detection_id": record["id"],
                "model_name": record["model"]["name"],
                "model_schema": record["model"]["schema"],
                "is_attack": int(record["is_attack"]),
            }
            buffer.seek(0)
            buffer.truncate(0)
            writer.writerow(row)
            yield buffer.getvalue()

    filename = f"ndr_detections_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/detections/{detection_id}")
def detection_detail(
    request: Request,
    detection_id: str,
    x_api_key: str | None = Header(default=None),
):
    _auth(request, x_api_key)
    source, _, raw_id = detection_id.partition(":")
    if source not in ("zeek", "cicids") or not raw_id.isdigit():
        raise HTTPException(
            status_code=422,
            detail="detection_id must look like 'zeek:12' or 'cicids:7'",
        )
    record = _store(request).get_detection(source, int(raw_id))
    if record is None:
        raise HTTPException(status_code=404, detail="detection not found")
    return record


@router.get("/sensors")
def sensors(request: Request, x_api_key: str | None = Header(default=None)):
    _auth(request, x_api_key)
    return sensor_payload(request.app.state)


@router.get("/models/status")
def models_status(request: Request, x_api_key: str | None = Header(default=None)):
    _auth(request, x_api_key)
    payload = overview_payload(request.app.state, window_s=300)
    return {
        "generated_at": payload["generated_at"],
        "models": payload["models"],
        "severity_policy": payload["severity_policy"],
        "counts": {
            "detections": payload["totals"]["detections"],
            "by_source": payload["totals"]["by_source"],
            "unclassified": payload["totals"]["unclassified"],
        },
    }


@router.get("/system/status")
def system_status(request: Request, x_api_key: str | None = Header(default=None)):
    method = _auth(request, x_api_key)
    return system_payload(request.app.state, auth_method=method)


@ws_router.websocket("/ws/alerts")
async def alerts_socket(websocket: WebSocket) -> None:
    """Authenticated alert stream.

    Browsers authenticate with the HttpOnly session cookie, which the browser
    attaches to the same-origin handshake. Scripts may pass ``?api_key=`` instead.
    Anything else is refused with close code 1008 before a byte is sent.
    """

    state = websocket.app.state
    settings = state.settings
    if not settings.auth_configured:
        await websocket.accept()
        await websocket.close(code=1013)
        return
    provided = websocket.query_params.get("api_key") or websocket.headers.get("x-api-key") or ""
    authorised = False
    if provided and provided.strip() == (settings.api_key or "").strip():
        authorised = True
    elif verify_session(settings, websocket.cookies.get(SESSION_COOKIE)):
        authorised = True
    if not authorised:
        await websocket.accept()
        await websocket.close(code=1008)
        return

    hub = state.hub
    if not await hub.register(websocket):
        await websocket.accept()
        await websocket.close(code=1013)
        return
    await websocket.accept()
    try:
        await websocket.send_json(
            {
                "type": "hello",
                "server_time": time.time(),
                "authenticated_by": "api_key" if provided else "session",
                "overview": overview_payload(state, window_s=settings.metrics_window_s),
            }
        )
        while True:
            try:
                await websocket.receive_text()
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    except Exception:  # noqa: BLE001 - a client that disappears is not an error
        log.debug("alert socket closed unexpectedly", exc_info=True)
    finally:
        await hub.unregister(websocket)
