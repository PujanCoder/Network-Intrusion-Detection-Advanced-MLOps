import logging

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel, Field

from src.serving.predictor import PredictorUnavailable, get_predictor
from src.serving.security import require_key
from src.serving.soc import broadcast_detection
from src.serving.status import health_payload, readiness

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1")


class FlowBatch(BaseModel):
    flows: list[dict] = Field(..., min_length=1, max_length=512)


@router.get("/health")
def health(request: Request):
    """Liveness + component report.

    Deliberately unauthenticated: hosting health checks and the dashboard need to
    distinguish "process down" from "deployment misconfigured". The body carries
    component state and no event data or secrets.
    """

    return health_payload(request.app.state)


@router.get("/ready")
def ready(request: Request):
    ok, payload = readiness(request.app.state)
    if not ok:
        raise HTTPException(status_code=503, detail=payload)
    return payload


@router.post("/ingest/cic")
async def ingest(
    batch: FlowBatch,
    request: Request,
    x_api_key: str | None = Header(default=None),
):
    require_key(request.app.state.settings, x_api_key)

    try:
        predictor = get_predictor()
    except PredictorUnavailable as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "cicids_model_unavailable",
                "message": "The CICIDS baseline artefacts are not present in this deployment.",
                "error": str(exc),
                "remediation": [
                    "Run `dvc pull` and ship models/best_model.joblib + models/preprocessor.joblib",
                    "or set IDS_MODEL_PATH and IDS_PREPROCESSOR_PATH to their location.",
                    "Zeek inference is unaffected and keeps working.",
                ],
                "health": "/api/v1/health",
            },
        ) from exc

    store = request.app.state.store

    preds = []
    for flow in batch.flows:
        pred = predictor.predict(flow)
        det_id = 0
        try:
            det_id = store.insert(flow, pred)
        except Exception:
            log.exception("store.insert failed")

        preds.append(pred)
        broadcast_detection(request.app.state, "cicids", det_id)

    return {"accepted": len(preds), "predictions": preds}
