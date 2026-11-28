"""The production NDR application.

One process serves everything the platform needs: the React SOC dashboard, the
authenticated metrics/detection/sensor APIs, CICIDS flow scoring, Zeek ingestion
and scoring, the alert WebSocket and the health endpoints. The dashboard bundle is
read from ``frontend/dist`` (``NDR_FRONTEND_DIST`` overrides), so no separate web
server or second deployment is involved.
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from src.ingestion.zeek.service import ZeekIngestionService
from src.serving.config import Settings
from src.serving.db import DetectionStore
from src.serving.predictor import load_predictor
from src.serving.routes import auth_routes, dashboard, ingest, soc, zeek
from src.serving.soc_store import SocStore
from src.serving.ws import Hub
from src.serving.zeek_predictor import load_zeek_predictor
from src.serving.zeek_store import ZeekStore

log = logging.getLogger(__name__)

TEMPLATE_PAGE = Path(__file__).parent / "templates" / "index.html"


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
    app.state.started_at = time.time()
    app.state.hub.bind_loop(asyncio.get_running_loop())
    _warm_models(settings)
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


def _warm_models(settings: Settings) -> None:
    """Load both scorers once at startup and log the outcome.

    Optional components (the CICIDS artefacts, the Zeek model) must never prevent
    the process from starting: their state is reported by /api/v1/health and
    /api/v1/ready instead.
    """

    cicids, cicids_error = load_predictor()
    zeek, zeek_error = load_zeek_predictor(settings.zeek_model_path)
    log.info(
        "startup: cicids_model=%s zeek_model=%s auth_configured=%s zeek_ingestion=%s",
        "loaded" if cicids else f"unavailable ({cicids_error})",
        "loaded" if zeek else f"unavailable ({zeek_error})",
        settings.auth_configured,
        settings.zeek_enabled,
    )


def _add_cache_headers(app: FastAPI) -> None:
    """Make a redeploy visible immediately without re-downloading hashed assets.

    ``index.html`` names content-hashed bundles, so it must always be revalidated;
    the bundles themselves never change under the same URL.
    """

    @app.middleware("http")
    async def cache_policy(request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.startswith("/assets/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        elif path in ("/", "/index.html") and response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response


def _mount_dashboard(app: FastAPI, settings: Settings) -> str:
    """Serve the React bundle when it exists, otherwise the built-in status page."""

    dist = Path(settings.frontend_dist)
    index = dist / "index.html"
    if index.is_file():
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="dashboard")
        return str(dist)
    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

    @app.get("/", include_in_schema=False)
    def legacy_dashboard() -> FileResponse:
        return FileResponse(TEMPLATE_PAGE)

    return str(TEMPLATE_PAGE)


def create_app() -> FastAPI:
    settings = Settings()
    app = FastAPI(title="NDR Platform", version="2.0.0", lifespan=lifespan)
    app.state.settings = settings
    app.state.store = DetectionStore(settings.db_path)
    app.state.zeek_store = ZeekStore(settings.db_path)
    app.state.soc_store = SocStore(settings.db_path)
    app.state.hub = Hub(settings.max_ws_clients)
    app.state.zeek_service = None
    app.state.started_at = time.time()

    app.include_router(ingest.router)
    app.include_router(zeek.router)
    app.include_router(soc.router)
    app.include_router(soc.ws_router)
    app.include_router(auth_routes.router)
    app.include_router(dashboard.router)
    _add_cache_headers(app)
    app.state.dashboard_source = _mount_dashboard(app, settings)
    log.info("dashboard source: %s", app.state.dashboard_source)
    return app


app = create_app()
