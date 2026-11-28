from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from src.ingestion.zeek.normalizers.base import normalize_record
from src.ingestion.zeek.schema import ZeekEventEnvelope
from src.ingestion.zeek.service import ZeekIngestionService
from src.serving.security import require_key
from src.serving.status import ingestion_state
from src.serving.zeek_predictor import predict_zeek_event, zeek_model_state

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/zeek")


class IngestDirRequest(BaseModel):
    log_dir: str = Field(..., min_length=1)
    sensor_id: str | None = None


class ZeekEventBatch(BaseModel):
    events: list[dict] = Field(..., min_length=1, max_length=2000)


class ZeekRecordsBatch(BaseModel):
    records: list[dict] = Field(..., min_length=1, max_length=500)
    sensor_id: str | None = None
    log_type: str | None = Field(default=None, description="Zeek log type; auto-detected when omitted")


def _score(store: Any, event: dict[str, Any]) -> dict[str, Any]:
    """Score one stored event and persist the detection row."""

    prediction = predict_zeek_event(event)
    store.insert_detection(event, prediction)
    return prediction


@router.get("/status")
def zeek_status(request: Request, x_api_key: str | None = Header(default=None)):
    require_key(request.app.state.settings, x_api_key)
    store = request.app.state.zeek_store
    return {
        "status": "ok",
        "counts": store.counts(),
        "sensors": store.status(),
        "ingestion": ingestion_state(request.app.state),
        "zeek_model": zeek_model_state(),
        "threshold": zeek_model_state()["threshold"],
    }


@router.get("/events")
def zeek_events(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    log_type: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None),
):
    require_key(request.app.state.settings, x_api_key)
    store = request.app.state.zeek_store
    return {"events": store.recent_events(limit=limit, log_type=log_type)}


@router.get("/detections")
def zeek_detections(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    only_attacks: bool = Query(default=False),
    x_api_key: str | None = Header(default=None),
):
    require_key(request.app.state.settings, x_api_key)
    store = request.app.state.zeek_store
    return {"detections": store.recent_detections(limit=limit, only_attacks=only_attacks)}


@router.post("/ingest/dir")
def ingest_dir(
    body: IngestDirRequest,
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    """Ingest Zeek JSON logs from a directory once. Restricted to configured allowed roots."""
    require_key(request.app.state.settings, x_api_key)
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
    require_key(request.app.state.settings, x_api_key)
    store = request.app.state.zeek_store
    inserted = 0
    duplicate = 0
    scored = 0
    unclassified = 0
    errors: list[str] = []
    for i, raw in enumerate(batch.events):
        try:
            env = ZeekEventEnvelope.model_validate(raw)
            event = env.model_dump()
            if store.insert_event(event):
                inserted += 1
                prediction = _score(store, event)
                if prediction.get("status") == "scored":
                    scored += 1
                else:
                    unclassified += 1
            else:
                duplicate += 1
        except Exception as e:  # noqa: BLE001 - per-record isolation
            log.exception("failed to ingest pushed zeek event %d", i)
            errors.append(f"{i}: {e}")
    return {
        "status": "ok",
        "inserted": inserted,
        "duplicate": duplicate,
        "scored": scored,
        "unclassified": unclassified,
        "errors": errors[:20],
    }


@router.post("/ingest/records")
def ingest_records(
    batch: ZeekRecordsBatch,
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    """Push raw Zeek JSON records; the server normalises, stores and scores them.

    This is the endpoint a remote sensor uses: it accepts the same objects Zeek
    writes to ``conn.log``/``dns.log`` with ``LogAscii::use_json = T``.
    """
    require_key(request.app.state.settings, x_api_key)
    settings = request.app.state.settings
    store = request.app.state.zeek_store
    sensor_id = batch.sensor_id or settings.zeek_sensor_id
    counts = {"inserted": 0, "duplicate": 0, "scored": 0, "unclassified": 0}
    errors: list[str] = []
    for i, record in enumerate(batch.records):
        try:
            env = normalize_record(
                record=record,
                source_file=f"remote:{sensor_id}:{batch.log_type or 'auto'}.log",
                source_offset=i,
                source_inode=None,
                sensor_id=sensor_id,
                log_type_hint=batch.log_type,
            )
            event = env.model_dump()
            if store.insert_event(event):
                counts["inserted"] += 1
                prediction = _score(store, event)
                counts["scored" if prediction.get("status") == "scored" else "unclassified"] += 1
            else:
                counts["duplicate"] += 1
        except Exception as e:  # noqa: BLE001 - per-record isolation
            log.exception("failed to ingest raw zeek record %d", i)
            errors.append(f"{i}: {e}")
    return {"status": "ok", "sensor_id": sensor_id, **counts, "errors": errors[:20]}
