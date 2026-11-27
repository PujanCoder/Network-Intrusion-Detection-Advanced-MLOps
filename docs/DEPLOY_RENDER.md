# Deploying the NDR platform on Render

The platform runs as **one Render web service** (Docker) that serves the API, the
WebSocket stream and the compiled React dashboard. The Zeek sensor stays on the
network you want to monitor and pushes records to that service over HTTPS.

```
        your network                                   Render
 ┌──────────────────────────┐                ┌───────────────────────────────┐
 │ Zeek (conn.log / dns.log)│                │  ndr-platform (Docker)        │
 │        │                 │  HTTPS POST    │  ┌─────────────────────────┐  │
 │        ▼                 │ ─────────────► │  │ FastAPI /api/ingest/zeek│  │
 │ scripts/zeek_forward.py  │  X-API-Key     │  │  ├ feature extraction   │  │
 └──────────────────────────┘                │  │  ├ zeek_model.joblib    │  │
                                             │  │  ├ behavioural detectors│  │
                                             │  │  └ SQLite (persistent)  │  │
                                             │  └───────────┬─────────────┘  │
                                             │              ▼                │
                                             │   REST + WebSocket (wss)      │
                                             │   React dashboard (/)         │
                                             └───────────────────────────────┘
```

## 1. What Render runs

| Component | Where | Notes |
| --- | --- | --- |
| FastAPI API + WebSocket | Render web service | `src.api.app:app`, honours `$PORT` |
| React dashboard | Same service | Built in the Docker image, served from `/` |
| SQLite database | `/var/data/ndr.db` | Requires a persistent disk (paid plan) |
| Live Zeek model | Image | `models/zeek/zeek_model.joblib` is committed (947 KB) |
| Zeek sensor | Your machine | Not deployable to Render; see §6 |

The batch CICIDS2017 artefacts (`models/best_model.joblib`, `models/preprocessor.joblib`)
are **not** needed by the web service. They are DVC-tracked and used by the
pipeline and the feature-contract test only.

## 2. Deploy the Blueprint

`render.yaml` in the repository root describes the service. Rendering a Blueprint
needs a Render account and one browser authorization, which cannot be performed
from CI or from an API key that does not exist yet:

1. Push this branch (already done).
2. Open <https://dashboard.render.com/blueprints> → **New Blueprint Instance**.
3. Select `PujanCoder/Network-Intrusion-Detection-Advanced-MLOps` and the branch
   `feature/realtime-ndr-platform`.
4. Render reads `render.yaml`, then asks for the `sync: false` secrets:
   - `NDR_API_KEY` — generate one with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
5. **Apply**. The first build takes ~6–10 minutes (Node build + Python deps).
6. Copy the service URL, e.g. `https://ndr-platform.onrender.com`.

Without a Blueprint you can create the service manually with the same values:
Docker environment, Dockerfile `deploy/Dockerfile.serving`, Docker context `.`,
health check path `/api/health`.

## 3. Environment variables

Only variables the application actually reads are listed.

| Variable | Required | Purpose |
| --- | --- | --- |
| `PORT` | injected by Render | Uvicorn binds this port; the Dockerfile falls back to 8000 |
| `NDR_API_KEY` | yes for a public deployment | Protects every `/api/*` route except `/api/health`, the WebSocket, **and enables remote ingestion** |
| `NDR_DB_PATH` | yes | `/var/data/ndr.db` (on the persistent disk) |
| `NDR_ZEEK_LOG_DIR` | optional | Local tail directory; unused on Render (`NDR_INGEST_ENABLED=false`) |
| `NDR_INGEST_ENABLED` | yes | `false` on Render: no Zeek process runs in the container |
| `NDR_SENSOR_MODE` | optional | Label shown in the UI (`remote`) |
| `NDR_FRONTEND_DIST` | yes | `/app/frontend/dist` |
| `NDR_RETENTION_DAYS` | optional | Event retention before the hourly purge (default 7) |
| `NDR_CORS_ORIGINS` | optional | Only needed if the dashboard is hosted on another origin |
| `NDR_INGEST_MAX_BATCH` | optional | Records accepted per push (default 500) |
| `DAGSHUB_USER_TOKEN` | pipeline only | Used by `dvc pull` / MLflow, never by the web service |
| `MLFLOW_TRACKING_URI` | pipeline only | Set by `src/models/tracking.py` at training time |
| `IDS_API_KEY` | legacy only | Guards the old `src/serving` app; not used by this service |

Secrets are set as **secret** environment variables in the Render dashboard. They
are never written to the repository, never baked into the image, and never
exposed to the frontend: the dashboard receives no `VITE_*` secret. Users type
the key into the dashboard, where it is stored in `localStorage` and sent as an
`X-API-Key` header (and as `?api_key=` on the WebSocket, which cannot set
headers).

## 4. Database persistence and plan limits

`render.yaml` mounts a **1 GB disk at `/var/data`**. Render disks require a paid
instance type (Starter and above). On the free plan:

- the container filesystem is **ephemeral** — the SQLite file disappears on every
  deploy, restart or spin-down after 15 minutes of inactivity;
- the service also cold-starts (~30 s) after idling.

Best free alternatives, in order of effort:

1. **Accept ephemeral storage for a demo** — remove the `disk:` block and set
   `NDR_DB_PATH=/tmp/ndr.db`. Events survive only while the instance is awake.
2. **Keep the sensor history locally** — run the API on your own machine with
   Docker Compose (SQLite on a real volume) and use Render only for a demo UI.
3. **Move the store to a managed database** — Render Postgres (free tier expires
   after 30 days) requires a storage abstraction that does not exist today; the
   `Store` class is SQLite-specific.

The honest summary: **durable event history on Render requires a paid plan.**

## 5. Verify the deployment

```bash
BASE=https://ndr-platform.onrender.com
KEY=...   # the NDR_API_KEY you configured

curl -s $BASE/api/health | jq '{status, model_loaded, database, remote_ingest_enabled}'
curl -s -H "X-API-Key: $KEY" $BASE/api/overview | jq '.total_events'
curl -s -H "X-API-Key: $KEY" $BASE/api/events?limit=5 | jq '.items | length'
curl -s -H "X-API-Key: $KEY" "$BASE/api/analytics?window=900" | jq 'keys'
curl -s -H "X-API-Key: $KEY" "$BASE/api/events/export.csv" | head -3
```

`/api/health` is deliberately unauthenticated so the platform health check and
the CI verifier can read it; it exposes only status, uptime, model flag and DB
integrity, never event contents.

Open `https://ndr-platform.onrender.com` — the dashboard prompts for the API key,
then connects to `wss://…/api/ws?api_key=…` (the client upgrades `ws:` to `wss:`
automatically on HTTPS pages).

## 6. Connect your local Zeek sensor

On the sensor host:

```bash
# 1. Make Zeek emit JSON so records map cleanly onto the API schema
echo 'redef LogAscii::use_json = T;' | sudo tee -a /opt/zeek/share/zeek/site/local.zeek
sudo /opt/zeek/bin/zeekctl deploy

# 2. Forward new conn.log records (offset is persisted in ~/.ndr-forward-state.json)
export NDR_API_KEY=...            # same key as the Render service
python scripts/zeek_forward.py \
    --url https://ndr-platform.onrender.com \
    --log /opt/zeek/logs/current/conn.log \
    --follow
```

The forwarder only sends complete lines, resumes from its saved offset, refuses
plain HTTP unless `--insecure` is passed for a lab, and reports per-batch counts
(`inserted`, `duplicates`, `predictions`, `alerts`, `rejected`). Server-side,
records are de-duplicated by event uid, so replaying a file never double-counts.

A single push can be tested without a sensor:

```bash
curl -s -X POST $BASE/api/ingest/zeek \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"sensor_id":"manual","log_type":"conn","records":[{
        "ts":1700000000.0,"uid":"Cmanual000001",
        "id.orig_h":"10.0.0.5","id.orig_p":41000,
        "id.resp_h":"10.0.0.9","id.resp_p":23,"proto":"tcp",
        "conn_state":"S0","orig_pkts":1,"resp_pkts":0}]}' | jq
```

Ingestion fails closed: with `NDR_API_KEY` unset the endpoint returns **503**;
with a wrong key it returns **401**; unknown log types return **422**; batches
above the limit return **413**.

## 7. CI/CD

`.github/workflows/deploy-render.yml` runs after **Continuous Integration**
succeeds on `main` or `feature/realtime-ndr-platform`, and on demand. Configure:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `RENDER_DEPLOY_HOOK_URL` | Render → service → Settings → Deploy Hook |
| Variable | `RENDER_HEALTH_URL` | `https://ndr-platform.onrender.com` |

Without `RENDER_DEPLOY_HOOK_URL` the workflow prints a notice and skips; it never
fails the pipeline and never exposes the hook in logs.

GitHub only registers `workflow_run` and `workflow_dispatch` workflows from the
**default branch**, so `deploy-render.yml` starts running after this branch is
merged into `main`. Until then Render still redeploys on push because
`render.yaml` sets `autoDeploy: true`; the workflow only adds the post-deploy
health verification.

## 8. Security notes

- TLS is terminated by Render; the container trusts proxy headers only because it
  is not directly reachable.
- The serving container needs no `NET_RAW`/`NET_ADMIN`; those belong to the
  sensor container only.
- Rate limiting is not implemented in-process; use Render's proxy limits or put
  Cloudflare in front if the endpoint is exposed to untrusted networks.
- Rotate `NDR_API_KEY` in the Render dashboard and on every sensor after any leak;
  the key is compared with `hmac.compare_digest`.

## 9. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Build fails at `npm ci` | `package-lock.json` out of sync | run `npm install` in `frontend/` and commit the lockfile |
| `/api/health` returns `model_loaded: false` | model file missing from the image | rebuild; `models/zeek/zeek_model.joblib` must be tracked by git |
| 401 on every call | key mismatch | compare `NDR_API_KEY` in Render with the dashboard's stored key |
| 503 on `/api/ingest/zeek` | `NDR_API_KEY` unset | set it; the endpoint is intentionally closed without a key |
| Events vanish after a deploy | no disk (free plan) | see §4 |
| WebSocket fails behind a proxy | client used `ws://` on an HTTPS page | the dashboard already upgrades to `wss://` |
