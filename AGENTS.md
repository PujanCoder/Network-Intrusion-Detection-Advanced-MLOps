# AGENTS.md

Repository notes for automated agents and contributors.

## Environment

- Python 3.13 at `/usr/local/bin/python`; run everything from the repository root.
- `requirements.txt` is UTF-8 (the old UTF-16 note was wrong; the BOM was removed).
- Frontend: Node 22+ / npm, Vite, React 19, TypeScript, Recharts.

## Commands

```bash
# tests (95)
PYTHONPATH=$PWD python -m pytest tests/ -q

# remote-ingestion smoke test against a running API
NDR_API_KEY=dev-key PYTHONPATH=$PWD python scripts/zeek_forward.py \
    --url http://127.0.0.1:8000 --log /tmp/conn.log --insecure

# backend + built dashboard
cd frontend && npm run build && cd ..
PYTHONPATH=$PWD python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000

# frontend type-check / build
cd frontend && npx tsc --noEmit && npm run build

# synthetic traffic without a sensor
NDR_SENSOR_MODE=replay PYTHONPATH=$PWD python scripts/replay_zeek_holdout.py --rate 2 --loop

# retrain the live model (writes models/zeek + reports/zeek_model)
PYTHONPATH=$PWD python -m src.realtime.training --output-dir models/zeek
```

## Deployment

- `render.yaml` is the single hosted-service definition (Docker, health check
  `/api/health`, disk at `/var/data`). `docs/DEPLOY_RENDER.md` is the operator guide.
- The service at `network-intrusion-detection-advanced.onrender.com` runs the **older**
  `src.serving` app (HTML dashboard, `/api/v1/*`), not `src.api`. It is documented in
  `docs/DEPLOY_SERVING.md` with the blueprint `deploy/render.serving.yaml`. Both apps accept
  `NDR_API_KEY` or `IDS_API_KEY`; data endpoints fail closed (`503 auth_not_configured` /
  `401 invalid_api_key`) and `/api/v1/health` is public on purpose.
- The hosted service sets `NDR_INGEST_ENABLED=false` (no Zeek in the container) and relies on
  `POST /api/ingest/zeek`, which **fails closed (503) unless `NDR_API_KEY` is set**. Sensors push
  with `scripts/zeek_forward.py`, which keeps a byte offset so restarts do not re-send.
- `deploy/Dockerfile.serving` binds `$PORT` and trusts proxy headers; Render terminates TLS in
  front of the container. `NDR_API_KEY` is a dashboard secret, never a `VITE_*` variable.
- `.github/workflows/deploy-render.yml` needs the `RENDER_DEPLOY_HOOK_URL` secret and the
  `RENDER_HEALTH_URL` variable; without them it prints a notice and skips. It uses
  `workflow_run`, so GitHub only registers it once the file is on `main`.
- Render disks require a paid plan. On the free plan SQLite is ephemeral (see the guide).

## Conventions and gotchas

- `src/realtime/store.py` owns all SQL. Writes go through `Store.transaction()` when several
  statements must be atomic (event + prediction + alerts); `_cursor()` only commits at depth 0.
- Never fabricate events or predictions. The dashboard must show "No new network events
  received." when the sensor is idle; `events_per_second_live` is a 10-second arrival rate,
  `events_per_second` is the 5-minute average.
- Replayed records carry `"_replay": true` in `raw_json`; `Store.replay_event_count()` drives
  the replay banner and `sensor.mode`.
- The live model is `models/zeek/zeek_model.joblib` (git-tracked on purpose); the batch model
  `models/best_model.joblib` is a DVC/pipeline artefact and stays ignored.
- `frontend/dist` and `frontend/node_modules` are gitignored; `scripts/run_api.sh` builds the
  bundle when it is missing.
- `.gitignore` has a Python-oriented `lib/` rule. `frontend/src/lib/` (the dashboard's shared
  API/types/format modules) is force-tracked at the bottom of `.gitignore`; if those modules
  ever go missing from a checkout, check that rule first.
- The delivered serving app is `src.serving` (`render.serving.yaml`), not `src.api`:
  Render only clones git, so its CICIDS artefacts must be fetched during the build with
  `python scripts/fetch_models.py` (DVC + `DAGSHUB_USER_TOKEN`, or `MODEL_ARTIFACTS_URL`).
  The script is non-fatal by design; `--strict` fails a build instead. `dvc push` in
  `.github/workflows/publish-artifacts.yml` is what puts the artefacts in the remote.
- Run `python scripts/check_dvc_deps.py` before any `dvc commit`/`dvc push`: DVC aborts on the
  first declared dependency that is absent, which is usually a stale or partial checkout, not a
  missing feature. The checker sorts deps into missing *source* (blocking: `git pull`),
  not-yet-built *output*, and DVC-tracked *input* (`dvc pull`).
- Batch artefacts are DVC-tracked (DagsHub HTTP remote). `tests/test_feature_contract.py`
  skips when `models/best_model.joblib` / `models/preprocessor.joblib` are absent; set
  `NDR_REQUIRE_ARTIFACTS=1` to turn that into a failure. Run `dvc pull` first.
- Detection results are decision support: in-distribution F1 ≈ 0.97, but cross-dataset
  transfer is weak and the zero-day probe scores 0 recall. Do not describe the model as
  production-ready.
