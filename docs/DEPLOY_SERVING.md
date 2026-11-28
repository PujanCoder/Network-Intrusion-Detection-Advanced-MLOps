# Deploying the NIDS serving app (the live dashboard)

This documents the service that runs at
`https://network-intrusion-detection-advanced.onrender.com` — the FastAPI app in
`src/serving`, which serves the HTML dashboard, the Zeek ingestion pipeline and
the CICIDS batch scoring endpoint.

There are **two** back-ends in this repository and they are not interchangeable:

| Module | Purpose | Routes | Frontend |
| --- | --- | --- | --- |
| `src.serving.app` | The deployed NIDS dashboard (serving + Zeek) | `/api/v1/*`, `/` | server-rendered `src/serving/templates/index.html` |
| `src.api.app` | The newer real-time platform | `/api/*`, `/api/ws` | `frontend/dist` (React) |

`render.yaml` at the repository root describes the *platform* service. The
serving app described here has its own blueprint: `deploy/render.serving.yaml`.

## Render configuration

The live service is a **Web Service → Python 3** (native runtime, not Docker):

| Setting | Value |
| --- | --- |
| Build command | `pip install -r requirements.txt` |
| Start command | `uvicorn src.serving.app:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*'` |
| Health check path | `/api/v1/health` |

Environment variables:

| Variable | Required | Meaning |
| --- | --- | --- |
| `NDR_API_KEY` **or** `IDS_API_KEY` | **yes** | API key for every data endpoint. Both names are accepted; set one. |
| `IDS_DB_PATH` | recommended | SQLite file, e.g. `/var/data/ids.db` (needs a Render disk mounted at `/var/data`, otherwise the database resets on every deploy). |
| `IDS_ZEEK_LOG_DIR` | no | Directory the in-process tailer watches. Defaults to `data/interim/zeek/current`, which does not exist in a container — harmless, the watcher simply finds nothing. |
| `IDS_ZEEK_ENABLED` | no | `true` only when Zeek writes logs into the container. Leave unset for push-based ingestion. |
| `IDS_MODEL_PATH`, `IDS_PREPROCESSOR_PATH` | no | Where the CICIDS artefacts live if you ship them (see below). |

Optional, to enable the CICIDS baseline on Render instead of only Zeek scoring:

```sh
# build command
pip install -r requirements.txt && dvc pull models/best_model.joblib models/preprocessor.joblib
```

with a `DAGSHUB_USER_TOKEN` secret available at build time. If the pull is
skipped the app still starts: `/api/v1/health` reports
`components.cicids_model.loaded = false` and `/api/v1/ingest/cic` answers `503`
with `code = "cicids_model_unavailable"`. Zeek inference does not depend on it.

## Opening the dashboard

The dashboard talks to the authenticated API, so it needs the key once:

```
https://<service>.onrender.com/?api_key=<the value of NDR_API_KEY>
```

The key is stored in the browser's `localStorage` (`ids_api_key`); the banner at
the top of the page tells you when it is missing.

## Feeding network events

The browser never asks a human to type flow features. Two machine paths exist:

1. **Push raw Zeek records** (works from anywhere, this is the path for a hosted
   deployment):

   ```sh
   curl -X POST "$BASE/api/v1/zeek/ingest/records" \
     -H "X-API-Key: $NDR_API_KEY" -H "Content-Type: application/json" \
     -d '{"records": [{"ts": 1700000000.0, "uid": "C1", "id.orig_h": "10.0.0.5", "id.orig_p": 41000,
                       "id.resp_h": "10.0.0.9", "id.resp_p": 23, "proto": "tcp", "service": "-",
                       "duration": 0.0, "orig_bytes": 0, "resp_bytes": 0, "conn_state": "S0",
                       "orig_pkts": 1, "resp_pkts": 0, "orig_ip_bytes": 60, "resp_ip_bytes": 0}],
        "sensor_id": "edge-1"}'
   ```

   The server normalises, stores idempotently, scores with the Zeek model and
   persists a detection row.

2. **Tail a local Zeek log directory** — set `IDS_ZEEK_ENABLED=true` and point
   `IDS_ZEEK_LOG_DIR` at a directory that Zeek writes (`LogAscii::use_json = T`).
   This only makes sense when Zeek runs in the same container/volume.

`POST /api/v1/zeek/ingest/events` accepts already-normalised event envelopes for
sensors that do their own normalisation.

## Docker

```sh
docker build -f deploy/Dockerfile.nids -t nids-serving .
docker run -p 8000:8000 -e PORT=8000 -e NDR_API_KEY=... \
  -v "$PWD/data:/app/data" nids-serving
```

The image ships the git-tracked Zeek model. The CICIDS artefacts are DVC-tracked
and are only present when they exist in the build context.

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `/api/v1/health` is `200` but every data call is `503` with `code=auth_not_configured` | no API key in the environment | set `NDR_API_KEY` (or `IDS_API_KEY`) and redeploy |
| data calls return `401` / `code=invalid_api_key` | key configured, wrong or missing header | open the dashboard as `/?api_key=...` |
| "Zeek Status: blocked" on the dashboard | the page has no key yet | open `/?api_key=...` once |
| `components.zeek_model.loaded = false` | `models/zeek/zeek_model.joblib` missing or a schema mismatch | keep the tracked artefact, or fix `IDS_ZEEK_MODEL_PATH`; the error text says which |
| `components.cicids_model.loaded = false` | DVC artefact not shipped | optional: run `dvc pull` during the build |
| Zeek Events stays 0 | nothing is being pushed and no log directory exists | use `/api/v1/zeek/ingest/records` or enable the tailer |
| Scored Detections stays 0 while events grow | every pushed event is a non-`conn` log, or the model failed to load | check the detection rows: `reason` explains it |
| data disappears after a deploy | SQLite lives on the ephemeral filesystem | mount a Render disk and set `IDS_DB_PATH=/var/data/ids.db` |
