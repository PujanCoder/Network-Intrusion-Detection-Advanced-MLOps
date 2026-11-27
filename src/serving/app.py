import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from src.serving.config import Settings
from src.serving.db import DetectionStore
from src.serving.ws import Hub
from src.serving.routes import ingest, dashboard

log = logging.getLogger(__name__)


def create_app() -> FastAPI:
    settings = Settings()
    app = FastAPI(title="NIDS Serving")
    app.state.settings = settings
    app.state.store = DetectionStore(settings.db_path)
    app.state.hub = Hub()

    app.include_router(ingest.router)
    app.include_router(dashboard.router)

    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


app = create_app()