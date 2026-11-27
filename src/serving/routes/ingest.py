import hmac
import logging

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from src.serving.predictor import get_predictor

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")


class FlowBatch(BaseModel):
    flows: list[dict] = Field(..., min_length=1, max_length=512)


def _check_key(request: Request, key: str | None) -> None:
    expected = getattr(request.app.state.settings, "api_key", "") or ""
    if not expected:
        raise HTTPException(status_code=503, detail="IDS_API_KEY is not configured")
    if not hmac.compare_digest(key or "", expected):
        raise HTTPException(status_code=401, detail="bad api key")


@router.get("/health")
def health(request: Request, x_api_key: str | None = Header(default=None)):
    _check_key(request, x_api_key)
    p = get_predictor()
    return {
        "status": "ok",
        "model": type(p.model).__name__,
        "input_features": len(p.feature_order),
        "model_features": len(p.model_features) if p.model_features else len(p.feature_order),
        "classes": p.classes,
    }


@router.post("/ingest/cic")
async def ingest(
    batch: FlowBatch,
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    _check_key(request, x_api_key)

    predictor = get_predictor()
    store = request.app.state.store
    hub = request.app.state.hub

    preds = []
    for flow in batch.flows:
        pred = predictor.predict(flow)
        try:
            store.insert(flow, pred)
        except Exception:
            log.exception("store.insert failed")

        preds.append(pred)

        if pred["is_attack"]:
            try:
                await hub.broadcast({
                    "type": "alert",
                    "flow": {k: flow.get(k) for k in
                             ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")},
                    "prediction": pred,
                })
            except Exception:
                log.exception("hub.broadcast failed")

    return {"accepted": len(preds), "predictions": preds}