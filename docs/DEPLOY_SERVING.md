# Deploying the NDR platform (one service, one URL)

The production service runs `src.serving.app`: a single FastAPI application that
serves the React SOC dashboard, the authenticated metrics/detection/sensor APIs,
CICIDS flow scoring, Zeek ingestion + scoring, the alert WebSocket and the health
endpoints. There is no second web server and no second deployment.

```
Browser ──HTTPS──> FastAPI (src.serving.app)
                     ├── /              React bundle (frontend/dist, committed)
                     ├── /api/v1/*      metrics, detections, sensors, models, system
                     ├── /api/v1/session login / logout (HttpOnly cookie)
                     ├── /api/v1/zeek/* ingestion + scoring (X-API-Key)
                     ├── /api/v1/ingest/cic CICIDS flow scoring (X-API-Key)
                     ├── /ws/alerts     authenticated alert stream
                     └── SQLite         zeek_events, zeek_detections, detections
```

`src.api.app` remains in the repository as the local/dev variant of the same idea.
It is no longer what the hosted service runs, and the dashboard no longer talks to
it: the bundle in `frontend/dist` is built against `/api/v1/*`.

## Render configuration

The live service (`network-intrusion-detection-advanced.onrender.com`) is a
**Web Service → Python** (native runtime, not Docker):

| Setting | Value |
| --- | --- |
| Branch | `feature/realtime-ndr-platform` — Render tracks this branch, **not** `main` |
| Build command | `pip install -r requirements.txt && python scripts/fetch_models.py && python scripts/verify_artifacts.py` |
| Start command | `uvicorn src.serving.app:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips='*'` |
| Health check | `/api/v1/health` |

Because the build command cannot install Node, the dashboard bundle is **committed**
(`frontend/dist`, see `.gitignore`). Any frontend change must ship with a rebuilt
bundle:

```bash
cd frontend && npm ci && npm run build && git add -A dist && git commit
```

The build is deterministic (same sources → same hashed filenames), so an unchanged
bundle produces no diff.

Environment variables:

| Variable | Required | Meaning |
| --- | --- | --- |
| `NDR_API_KEY` **or** `IDS_API_KEY` | **yes** | The only secret. Authenticates `X-API-Key` clients and underwrites the dashboard session tokens. |
| `IDS_DB_PATH` | recommended | SQLite file, e.g. `/var/data/ids.db`. Without a Render disk the file resets on every deploy. |
| `NDR_SESSION_SECRET` | no | Signing key for session cookies. Derived from the API key when unset (so rotating the key logs everyone out). |
| `IDS_SESSION_TTL_S` | no | Session lifetime, default `28800` (8 h). |
| `IDS_SESSION_COOKIE_SECURE` | no | `true` forces the `Secure` flag. Unset = decided per request (`https` or `X-Forwarded-Proto: https`). |
| `NDR_FRONTEND_DIST` | no | Where the bundle lives, default `frontend/dist` relative to the repository root. |
| `IDS_SENSOR_STALE_AFTER_S` | no | A sensor is "online" only if an event arrived within this window (default 300 s). |
| `IDS_ZEEK_ENABLED` / `IDS_ZEEK_LOG_DIR` | no | Enable the in-process log tailer. Leave off for push-based sensors. |
| `DAGSHUB_USER_TOKEN`, `DAGSHUB_USERNAME` | build only | Let the build fetch DVC artefacts when they are not committed. |

## Authentication

Two mechanisms, one secret:

- **Machines** (`curl`, sensors, CI) send `X-API-Key: $NDR_API_KEY`.
- **Browsers** post the key once to `POST /api/v1/session`; the server verifies it
  and returns `ndr_session`, an HMAC-signed token in an `HttpOnly`, `SameSite=Lax`
  cookie. JavaScript never sees the key or the token.

The cookie authorises **reads only**. Ingestion endpoints (`POST /api/v1/zeek/*`,
`POST /api/v1/ingest/cic`) require the header, so a cross-site request cannot push
events. `/ws/alerts` accepts the cookie (same-origin handshake) or `?api_key=` for
scripts, and closes with code `1008` otherwise.

With no key configured the process still starts (health reports it) but every data
endpoint returns `503 auth_not_configured` — fail closed, with a remediation list.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/api/v1/health` | public | component state, build commit, DB integrity, models |
| GET | `/api/v1/ready` | public | readiness for the deployed mode |
| GET | `/api/v1/metrics/overview` | yes | totals, rates, distributions, series, sensors, models, recent |
| GET | `/api/v1/metrics/live` | yes | recent detections + `no_new_events` verdict |
| GET | `/api/v1/detections` | yes | filters, search, pagination (`limit` ≤ 200) |
| GET | `/api/v1/detections/{id}` | yes | `zeek:12` / `cicids:7`, full record + raw JSON |
| GET | `/api/v1/detections/export` | yes | same filters, streamed CSV |
| GET | `/api/v1/sensors` | yes | per-sensor counters and timestamp-based liveness |
| GET | `/api/v1/models/status` | yes | both models, schemas, runtime counters, latency policy |
| GET | `/api/v1/system/status` | yes | composed health, DB, WebSocket, build, endpoints |
| GET/POST/DELETE | `/api/v1/session` | mixed | session state, login, logout |
| WS | `/ws/alerts` | yes | `hello`, `event` messages |
| POST | `/api/v1/zeek/ingest/records` | key | sensor push (normalise, store, score, broadcast) |
| POST | `/api/v1/ingest/cic` | key | CICIDS flow scoring |

## Verifying a deploy

```bash
BASE=https://network-intrusion-detection-advanced.onrender.com
curl -s $BASE/api/v1/health | jq '{status, build, models}'        # commit + models loaded
curl -s -o /dev/null -w '%{http_code}\n' $BASE/api/v1/detections # 401 without a key
curl -s -H "X-API-Key: $NDR_API_KEY" $BASE/api/v1/metrics/overview | jq '.totals'
curl -s $BASE/ | grep -o 'assets/index-[^"]*\.js'                # dashboard bundle
```

`build.commit` must equal the commit you intended to deploy. A stale commit means
the tracked branch was not the one you pushed (Render follows
`feature/realtime-ndr-platform`).

## Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `503 auth_not_configured` | no key in the environment | set `NDR_API_KEY`, redeploy |
| Dashboard shows the login screen but rejects the key | key mismatch (whitespace) | paste the exact value; check `auth.source` in `/api/v1/health` |
| Login succeeds, reads return 401 | `Secure` cookie over plain HTTP | use HTTPS or set `IDS_SESSION_COOKIE_SECURE=false` locally |
| WebSocket closes with `1008` | no session and no `?api_key` | sign in first, or pass the key explicitly |
| Dashboard empty, "No new network events received." | nothing ingested yet | push a sensor batch or enable local ingestion |
| Everything zero after a deploy | SQLite on ephemeral disk | mount a disk at `/var/data` and set `IDS_DB_PATH` |
| CICIDS `loaded: false` | artefacts missing | run `python scripts/fetch_models.py` in the build; it explains which check failed |
