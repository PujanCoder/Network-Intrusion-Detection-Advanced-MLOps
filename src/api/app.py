"""FastAPI application for the real-time NDR platform.

Replaces the earlier Flask stub (which imported an empty blueprint) with the
async API the dashboard needs: REST queries, a WebSocket live stream and the
built React dashboard served from ``frontend/dist``.

Run locally::

    uvicorn src.api.app:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from src.api.predictor import ModelService
from src.api.routes import router
from src.realtime.broadcast import ConnectionManager
from src.realtime.config import Settings, get_settings
from src.realtime.model import ZeekModel
from src.realtime.service import IngestionService
from src.realtime.store import Store

logger = logging.getLogger(__name__)

APP_VERSION = "2.0.0"


@dataclass
class AppState:
    settings: Settings
    store: Store
    model: ZeekModel
    hub: ConnectionManager
    service: IngestionService | None
    model_service: ModelService
    started_at: float


def _overview_payload(state: AppState) -> dict[str, Any]:
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


async def _metrics_ticker(app: FastAPI) -> None:
    """Broadcast DB-derived metrics once per second to connected dashboards.

    Metrics are recomputed from persisted events; nothing is fabricated when
    traffic is idle.
    """

    state: AppState = app.state.ndr
    while True:
        await asyncio.sleep(state.settings.ws_metrics_interval_s)
        try:
            if state.hub.client_count == 0:
                continue
            payload = await asyncio.to_thread(_overview_payload, state)
            await state.hub.broadcast({"type": "metrics", "overview": payload, "ts": time.time()})
        except asyncio.CancelledError:
            raise
        except Exception:  # pragma: no cover - keep the ticker alive
            logger.exception("Metrics ticker error")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = Store(settings.db_path)
        model = ZeekModel(settings.model_path)
        if not model.load():
            logger.warning("Live model unavailable: %s", model.load_error)

        hub = ConnectionManager(settings.max_ws_clients, settings.ws_queue_size)
        hub.bind_loop(asyncio.get_running_loop())

        service = None
        if settings.ingest_enabled:
            service = IngestionService(settings, store, model, publisher=hub.publish_threadsafe)
            service.start()

        app.state.ndr = AppState(
            settings=settings,
            store=store,
            model=model,
            hub=hub,
            service=service,
            model_service=ModelService(model, store),
            started_at=time.time(),
        )
        ticker = asyncio.create_task(_metrics_ticker(app))
        try:
            yield
        finally:
            ticker.cancel()
            try:
                await ticker
            except (asyncio.CancelledError, Exception):
                pass
            if service is not None:
                service.stop()
            store.close()

    app = FastAPI(
        title="Advanced Real-Time NDR Platform",
        description=(
            "Zeek log ingestion, ML flow classification, behavioural detection "
            "and live security monitoring."
        ),
        version=APP_VERSION,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["*"],
    )
    @app.middleware("http")
    async def enforce_api_key(request: Request, call_next):
        state = getattr(request.app.state, "ndr", None)
        key = state.settings.api_key if state else None
        path = request.url.path
        if key and path.startswith("/api") and path != "/api/health":
            provided = request.headers.get("x-api-key", "")
            auth = request.headers.get("authorization", "")
            if not provided and auth.lower().startswith("bearer "):
                provided = auth[7:].strip()
            if not hmac.compare_digest(provided, key):
                return JSONResponse({"detail": "invalid or missing API key"}, status_code=401)
        return await call_next(request)

    app.include_router(router, prefix="/api")

    dist = settings.frontend_dist
    if dist.exists() and (dist / "index.html").exists():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="dashboard")
    else:
        @app.get("/")
        def dashboard_missing() -> JSONResponse:
            return JSONResponse(
                {
                    "message": "Dashboard bundle not built.",
                    "build": "cd frontend && npm install && npm run build",
                    "api_docs": "/docs",
                }
            )

    return app


app = create_app()
