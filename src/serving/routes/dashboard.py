from pathlib import Path

from fastapi import APIRouter, Header, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from src.serving.security import require_key

router = APIRouter()


@router.get("/")
def index():
    p = Path(__file__).resolve().parents[1] / "templates" / "index.html"
    return FileResponse(p)


@router.get("/api/v1/detections")
def list_detections(
    request: Request,
    limit: int = 100,
    only_attacks: bool = False,
    x_api_key: str | None = Header(default=None),
):
    """Detection history. Same key as every other data endpoint: the rows carry
    internal addresses and classifications, so the endpoint fails closed."""

    require_key(request.app.state.settings, x_api_key)
    return request.app.state.store.recent(limit=limit, only_attacks=only_attacks)


@router.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await ws.accept()
    hub = ws.app.state.hub
    await hub.register(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await hub.unregister(ws)