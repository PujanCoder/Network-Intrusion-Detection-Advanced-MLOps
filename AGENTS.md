# AGENTS.md

Repository notes for automated agents and contributors.

## Environment

- Python 3.13 at `/usr/local/bin/python`; run everything from the repository root.
- `requirements.txt` is UTF-8 (the old UTF-16 note was wrong; the BOM was removed).
- Frontend: Node 22+ / npm, Vite, React 19, TypeScript, Recharts.

## Commands

```bash
# tests (201)
PYTHONPATH=$PWD python -m pytest tests/ -q

# remote-ingestion smoke test against a running API
NDR_API_KEY=dev-key PYTHONPATH=$PWD python scripts/zeek_forward.py \
    --url http://127.0.0.1:8000 --log /tmp/conn.log --insecure

# backend + built dashboard (production app, sign in with the key)
cd frontend && npm run build && cd ..
NDR_API_KEY=dev-key PYTHONPATH=$PWD python -m uvicorn src.serving.app:app --host 0.0.0.0 --port 8000

# frontend type-check / build
cd frontend && npx tsc --noEmit && npm run build

# synthetic traffic without a sensor
NDR_SENSOR_MODE=replay PYTHONPATH=$PWD python scripts/replay_zeek_holdout.py --rate 2 --loop

# retrain the live model (writes models/zeek + reports/zeek_model)
PYTHONPATH=$PWD python -m src.realtime.training --output-dir models/zeek
```

## Deployment

- `render.yaml` is the single hosted-service definition (Docker, health check
  `/api/v1/health`, disk at `/var/data`). `docs/DEPLOY_RENDER.md` is the operator guide,
  `docs/DEPLOY_SERVING.md` the production one.
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
- Both serving artefacts are git-tracked: `models/zeek/zeek_model.joblib` and the CICIDS
  pair (`models/best_model.joblib`, `models/preprocessor.joblib`), so a Render build loads
  them from the clone and needs no DVC access. `dvc.lock` is kept in step with the committed
  bytes, and the same objects are also pushed to the DagsHub remote as a fallback.
  `tests/test_committed_artifacts.py` guards the contract (78 features in, 68 to the
  estimator, classes BENIGN/DDoS) using two real CICIDS2017 flows as fixtures.
- **`frontend/dist` is committed** (`.gitignore` explains why): the Render build command
  cannot run Node, so the service serves the bundle straight from the clone. After any
  frontend change run `cd frontend && npm run build` and commit the regenerated `dist` —
  the build is deterministic, so no diff means nothing changed. `frontend/node_modules` is
  still ignored.
- The production app is `src.serving.app` and it serves everything: `/` (React), `/api/v1/*`,
  `/ws/alerts`, `/api/v1/ingest/cic`, `/api/v1/zeek/*`. `src.api.app` is the dev variant on
  `/api`; the dashboard no longer calls it. Don't reintroduce a second deployment.
- Browser auth is a session cookie, never a key in the bundle: `POST /api/v1/session`
  verifies `NDR_API_KEY` and returns `ndr_session` (HMAC-signed, HttpOnly, SameSite=Lax,
  TTL `IDS_SESSION_TTL_S`). Cookies authorise **reads only**; ingestion requires
  `X-API-Key`, which is what keeps writes out of CSRF reach. `src/serving/security.py`
  owns this; `tests/test_soc_api.py` pins the contract (401/503/1008, tamper, expiry,
  throttle).
- The dashboard is 8 pages (`/#/`, `#/live`, `#/threats`, `#/investigate`, `#/sensors`,
  `#/models`, `#/system`, `#/analytics`). All numbers come from `/api/v1/*` SQL; the only
  derived value is `severity`, and every record carries `severity_source` to say so.
- `.gitignore` has a Python-oriented `lib/` rule. `frontend/src/lib/` (the dashboard's shared
  API/types/format modules) is force-tracked at the bottom of `.gitignore`; if those modules
  ever go missing from a checkout, check that rule first.
- The live Render service `network-intrusion-detection-advanced` tracks the branch
  `feature/realtime-ndr-platform`, not `main`; `/api/v1/health` reports the commit it is
  running under `build`. Deploying main means fast-forwarding that branch to the merge
  commit and POSTing `RENDER_DEPLOY_HOOK_URL` (the hook rebuilds whatever the branch holds).
- `/api/v1/detections` accepts `X-API-Key` or the dashboard session; the React page itself
  is a static asset, but every datum behind it is authenticated. `detection_id` values are
  `zeek:<rowid>` / `cicids:<rowid>`.
- The delivered serving app is `src.serving` (`render.serving.yaml`), not `src.api`:
  Render only clones git, so its CICIDS artefacts must be fetched during the build with
  `python scripts/fetch_models.py` (DVC + `DAGSHUB_USER_TOKEN`, or `MODEL_ARTIFACTS_URL`).
  The script is non-fatal by design; `--strict` fails a build instead. `dvc push` in
  `.github/workflows/publish-artifacts.yml` is what puts the artefacts in the remote.
- The DagsHub remote is the HTTPS `.dvc` endpoint, so it uses basic auth (`auth`/`user`/
  `password`). S3 options in `.dvc/config.local` make DVC refuse to start with
  `extra keys not allowed`; `scripts/dvc_remote.py --fix` strips them and
  `scripts/fetch_models.py` runs that repair before every pull.
- Publishing is `python scripts/dvc_publish.py`: it repairs the config, verifies both
  artefacts through `src.serving.predictor`, locks them (commit or surgical relock),
  pushes and verifies with `dvc status -c` + an authenticated HEAD per object.
  It re-locks `dvc.lock` when the local artefacts differ from the recorded hashes;
  that change must be committed and pushed or the deploy resolves old objects.
- Run `python scripts/check_dvc_deps.py` before any `dvc commit`/`dvc push`: DVC aborts on the
  first declared dependency that is absent, which is usually a stale or partial checkout, not a
  missing feature. The checker sorts deps into missing *source* (blocking: `git pull`),
  not-yet-built *output*, and DVC-tracked *input* (`dvc pull`).
- The raw dataset stays DVC-tracked (DagsHub HTTP remote, 8 CICIDS2017 CSVs); only the
  serving artefacts are committed. `tests/test_feature_contract.py` skips when
  `models/best_model.joblib` / `models/preprocessor.joblib` are absent; set
  `NDR_REQUIRE_ARTIFACTS=1` to turn that into a failure.
- Serving sanitises before transforming: real captures carry `inf` in rate features when
  duration is 0, and the training pipeline replaced those with the column median. The bundle
  does not carry the medians, so `Predictor._sanitise` coerces to numeric and fills the gaps
  with 0.0 — without it, a legitimate flow raises `ValueError` inside PowerTransformer.
- Detection results are decision support: in-distribution F1 ≈ 0.97, but cross-dataset
  transfer is weak and the zero-day probe scores 0 recall. Do not describe the model as
  production-ready.
