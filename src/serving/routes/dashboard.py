from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect

router = APIRouter()


@router.get("/api/v1/detections")
def list_detections(request: Request, limit: int = 100, only_attacks: bool = False):
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