import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from src.serving.config import Settings
from src.serving.db import DetectionStore
from src.serving.ws import Hub
from src.serving.zeek_store import ZeekStore
from src.serving.routes import dashboard, ingest, zeek
from src.ingestion.zeek.service import ZeekIngestionService

log = logging.getLogger(__name__)


def _build_zeek_service(settings: Settings) -> ZeekIngestionService:
    return ZeekIngestionService(
        db_path=settings.db_path,
        log_dir=settings.zeek_log_dir,
        sensor_id=settings.zeek_sensor_id,
        log_types=settings.zeek_log_types,
        poll_interval=settings.zeek_poll_interval,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    svc: ZeekIngestionService | None = None
    if settings.zeek_enabled:
        try:
            svc = _build_zeek_service(settings)
            svc.start_background()
            app.state.zeek_service = svc
            log.info("zeek ingestion background service started")
        except Exception:  # noqa: BLE001
            log.exception("failed to start zeek ingestion service")
    yield
    if svc is not None:
        try:
            await svc.stop()
        except Exception:  # noqa: BLE001
            log.exception("failed to stop zeek ingestion service")


def create_app() -> FastAPI:
    settings = Settings()
    app = FastAPI(title="NIDS Serving", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = DetectionStore(settings.db_path)
    app.state.zeek_store = ZeekStore(settings.db_path)
    app.state.hub = Hub()
    app.state.zeek_service = None

    app.include_router(ingest.router)
    app.include_router(dashboard.router)
    app.include_router(zeek.router)

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


app = create_app()