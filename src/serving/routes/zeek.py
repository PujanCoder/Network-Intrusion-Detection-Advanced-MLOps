from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from src.ingestion.zeek.schema import ZeekEventEnvelope
from src.ingestion.zeek.service import ZeekIngestionService

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/zeek")


def _check_key(request: Request, key: str | None) -> None:
    expected = getattr(request.app.state.settings, "api_key", None)
    if expected and key != expected:
        raise HTTPException(status_code=401, detail="bad api key")


class IngestDirRequest(BaseModel):
    log_dir: str = Field(..., min_length=1)
    sensor_id: str | None = None


class ZeekEventBatch(BaseModel):
    events: list[dict] = Field(..., min_length=1, max_length=2000)


@router.get("/status")
def zeek_status(request: Request, x_api_key: str | None = Header(default=None)):
    _check_key(request, x_api_key)
    store = request.app.state.zeek_store
    return {
        "status": "ok",
        "counts": store.counts(),
        "sensors": store.status(),
        "ingestion_enabled": bool(getattr(request.app.state.settings, "zeek_enabled", False)),
        "log_dir": str(getattr(request.app.state.settings, "zeek_log_dir", "")),
    }


@router.get("/events")
def zeek_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    log_type: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None),
):
    _check_key(request, x_api_key)
    store = request.app.state.zeek_store
    return {"events": store.recent_events(limit=limit, log_type=log_type)}


@router.get("/detections")
def zeek_detections(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    only_attacks: bool = Query(default=False),
    x_api_key: str | None = Header(default=None),
):
    _check_key(request, x_api_key)
    store = request.app.state.zeek_store
    return {"detections": store.recent_detections(limit=limit, only_attacks=only_attacks)}


@router.post("/ingest/dir")
def ingest_dir(
    body: IngestDirRequest,
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    """Ingest Zeek JSON logs from a directory once. Restricted to configured allowed roots."""
    _check_key(request, x_api_key)
    settings = request.app.state.settings
    requested = Path(body.log_dir).resolve()
    allowed_roots = [
        Path(settings.zeek_log_dir).resolve(),
        Path(settings.zeek_run_dir).resolve(),
        Path(settings.zeek_pcap_dir).resolve(),
        Path("data/interim/zeek").resolve(),
    ]
    if not any(requested == root or root in requested.parents for root in allowed_roots):
        raise HTTPException(status_code=403, detail="log_dir not allowed")

    if not requested.exists() or not requested.is_dir():
        raise HTTPException(status_code=404, detail="log_dir not found")

    svc = ZeekIngestionService(
        db_path=settings.db_path,
        log_dir=requested,
        sensor_id=body.sensor_id or settings.zeek_sensor_id,
        log_types=settings.zeek_log_types,
    )
    counts = svc.ingest_once()
    return {"status": "ok", "log_dir": str(requested), "counts": counts}


@router.post("/ingest/events")
def ingest_events(
    batch: ZeekEventBatch,
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    """Push pre-normalized Zeek event envelopes (remote sensor mode). Idempotent by event_id."""
    _check_key(request, x_api_key)
    store = request.app.state.zeek_store
    inserted = 0
    duplicate = 0
    errors: list[str] = []
    for i, raw in enumerate(batch.events):
        try:
            env = ZeekEventEnvelope.model_validate(raw)
            ok = store.insert_event(env.model_dump())
            if ok:
                inserted += 1
            else:
                duplicate += 1
        except Exception as e:  # noqa: BLE001
            errors.append(f"{i}: {e}")
    return {"status": "ok", "inserted": inserted, "duplicate": duplicate, "errors": errors[:20]}
