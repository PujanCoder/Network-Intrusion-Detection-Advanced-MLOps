# Advanced Real-Time Network Detection and Response (NDR) Platform

A Zeek-driven network detection platform with a multi-dataset flow classifier, rule-based
detectors, a FastAPI backend and a live security dashboard — built on top of the original
CICIDS2017 intrusion-detection ML pipeline, which is still in the repository and still runs.

> **Read this before trusting a number.** The live classifier is trained on public datasets
> (CICIDS2017, UNSW-NB15, NSL-KDD). Its in-distribution scores are strong, its cross-dataset
> transfer is weak (0% recall on an unseen dataset in the zero-day probe), and the API has no
> authentication. It is a decision-support tool, not an unattended production sensor.

---

## What works today

| Capability | State |
|---|---|
| Zeek `conn.log` ingestion (TSV and JSON) | Implemented, tested |
| Incremental tailing with rotation / truncation / partial-line handling | Implemented, tested |
| SQLite persistence with duplicate protection | Implemented, tested |
| 23-feature extractor shared by training and inference | Implemented, tested |
| Multi-dataset model training + evaluation + model card | Executed (`models/zeek`, `reports/zeek_model`) |
| 10 rule-based behavioural detectors | Implemented, tested |
| FastAPI REST + WebSocket API | Implemented, tested, executed |
| React dashboard, 6 pages, live updates | Built, executed in a browser |
| 85 automated tests | Passing |
| Batch CICIDS2017 pipeline (MLflow/DagsHub/DVC) | Preserved |
| Live Zeek capture on a real interface | **Not verified here** (no Zeek in this container) |

Full detail: [`docs/PROJECT_ARCHITECTURE.md`](docs/PROJECT_ARCHITECTURE.md).

---

## Quick start

```bash
python -m pip install -r requirements.txt

cd frontend && npm ci && npm run build && cd ..

PYTHONPATH=$PWD python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
```

Open <http://localhost:8000>. The dashboard is served from `frontend/dist`; the API is under
`/api`.

Or run both containers (Zeek sensor + API/dashboard) with Compose:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

The sensor container needs `NET_RAW`/`NET_ADMIN` and a real interface (`IFACE=eth0`).

Frontend development with hot reload:

```bash
cd frontend && npm install && npm run dev     # http://localhost:5173
```

### Feed it traffic

Real Zeek sensor (needs Zeek and an interface):

```bash
sudo ./scripts/zeek_live.sh -i eth0
```

Replay without a sensor:

```bash
NDR_SENSOR_MODE=replay PYTHONPATH=$PWD python scripts/replay_zeek_holdout.py --rate 2 --loop
```

Replayed records are tagged `"_replay": true`. The API reports `sensor.mode = "replay"` and the
dashboard shows a **Replay data detected** banner — a replay can never be mistaken for live
capture. With no traffic arriving the dashboard says **"No new network events received."**
instead of inventing activity.

### Tests

```bash
PYTHONPATH=$PWD python -m pytest tests/ -q      # 85 passed
cd frontend && npx tsc --noEmit && npm run build
```

---

## Architecture at a glance

```
Zeek conn.log ──► reader.py ──► zeek_parser.py ──► features.py ──┬──► model.py (HGB classifier)
                                                                 └──► detectors.py (10 rules)
                                        │
                                        ▼
                                   store.py (SQLite: events, predictions, alerts,
                                             ingestion_state, dead_letters, service_state)
                                        │
                                        ▼
                        broadcast.py (WebSocket fan-out) ──► FastAPI ──► React dashboard
```

- **Ingestion** — one daemon thread polls the log directory every 0.5 s, reads only new bytes,
  and persists offsets so a restart resumes exactly where it stopped.
- **Detection** — the model scores `conn` flows; rule detectors run independently and add
  severity, category and evidence. Alerts are de-duplicated per event and rule.
- **Serving** — REST for history and aggregates, WebSocket for live events and per-second
  metrics. Every number shown comes from SQLite.
- **Honesty** — measured inference latency, measured event→database delay, explicit
  `no_new_events` flag, and a replay banner.

---

## Model

| | |
|---|---|
| Artefact | `models/zeek/zeek_model.joblib` (+ metadata JSON) |
| Version | `2026.11.27-37f7a80` |
| Algorithm | HistGradientBoosting, operating threshold 0.95 (5% FPR budget) |
| Training data | CICIDS2017 225,745 · UNSW-NB15 82,332 · NSL-KDD 125,973 |
| Split | train 208,755 / validation 44,733 / test 44,734, stratified by (dataset, label) |
| Test (all) | precision 0.963 · recall 0.983 · F1 0.973 · FPR 0.0356 |
| UNSW-NB15 official test | precision 0.941 · recall 0.937 · F1 0.939 · FPR 0.125 |
| NSL-KDD official test | precision 0.943 · recall 0.492 · F1 0.647 · FPR 0.039 |
| Zero-day probe (trained without NSL-KDD) | recall 0.00 at 0.00 FPR — does not transfer |
| Inference latency | p50 2.23 ms, p95 2.92 ms, 432 flows/s (2,000 flows, measured) |

Retrain:

```bash
PYTHONPATH=$PWD python -m src.realtime.training --output-dir models/zeek
```

Outputs: model + metadata, `reports/zeek_model/evaluation.json`, threshold sweep, sampled
false positives/negatives, and `model_card.md`.

The original batch model (`models/best_model.joblib`, Logistic Regression / Decision Tree /
Random Forest on CICIDS2017) is untouched and is reported separately by `GET /api/model` under
`batch_model`.

---

## Batch pipeline (DVC + MLflow)

The CICIDS2017 pipeline is still orchestrated by DVC and tracked in MLflow:

```bash
python -m dvc repro            # clean -> preprocess -> train -> evaluate -> validate
python -m dvc status
```

Stages (`dvc.yaml`): `ml_pipeline` (the whole batch run) and `validate_preprocessor`
(read-only check that the saved preprocessor and batch model agree). The two stages never
write the same artefact, so `models/preprocessor.joblib` has a single owner.

Artefacts (`data/processed/`, `models/best_model.joblib`, `models/preprocessor.joblib`) are
DVC-tracked and gitignored. The remote is the DagsHub DVC endpoint:

```bash
# one-time, per machine; credentials go to .dvc/config.local (never committed)
python -m dvc remote modify origin --local auth basic
python -m dvc remote modify origin --local user <dagshub-user>
python -m dvc remote modify origin --local password <dagshub-token>

python -m dvc pull      # fetch artefacts on a fresh clone / CI runner
python -m dvc push      # publish artefacts you just reproduced
```

MLflow tracking uses `DAGSHUB_USER_TOKEN` when it is set and otherwise falls back to a local
`sqlite:///mlflow.db` store, so the pipeline runs offline and on CI without credentials.

The `tests/test_feature_contract.py` contract test needs the two model artefacts. It is
skipped when they are absent; set `NDR_REQUIRE_ARTIFACTS=1` to make a missing artefact a hard
failure (CI sets it after a successful `dvc pull`).

---

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness, uptime, DB integrity, ingestion flags |
| GET | `/api/overview` | KPI counters, rolling rates, model and sensor summary |
| GET | `/api/events` | filters: `search`, `proto`, `prediction`, `severity`, `start`, `end`, `malicious_only` |
| GET | `/api/events/export.csv` | same filters, streamed CSV |
| GET | `/api/events/{id}` | full record, prediction, alerts, original Zeek JSON |
| GET | `/api/attacks` | ML attacks + HIGH/CRITICAL rule alerts |
| GET | `/api/analytics` | time series, distributions, top talkers, confidence histogram |
| GET | `/api/model` | live model vs batch model, runtime counters |
| GET | `/api/detections` | rule hit counts and detector catalogue |
| GET | `/api/sensors` | sensor state, ingestion offsets, DB/API/WS status, processing delay |
| WS | `/api/ws` | `hello`, `event`, `metrics`, `ping` |

---

## Dashboard

| Page | What it shows |
|---|---|
| Overview | sensor/model status, total events, events and predictions per second, attacks, benign, suspicious, unclassified, critical alerts, traffic mix, 15-minute rate chart, latest predictions |
| Live stream | continuously updating table (timestamp, endpoints, ports, proto, state, prediction, confidence, severity, explanation), malicious rows highlighted |
| Traffic analytics | rates, volume, benign vs attack mix, attack classes, protocol mix, severity, top sources and destinations, confidence histogram |
| Attack monitoring | detections with timestamps, endpoints, category, severity, confidence, evidence, history |
| Model monitoring | active model, version, training data, feature schema, evaluation table, confusion matrix, importance, latency, unclassified count |
| Event explorer | IP/protocol/prediction/severity/time filters, pagination, JSON drawer, CSV export |
| Sensor health | Zeek capture state, counters, event→DB delay, database/API/WebSocket status, detector list |

---

## Repository layout

```
src/api/            FastAPI app, routes, model service
src/realtime/       Zeek parsing, reader, features, model, detectors, store, service, training
src/pipelines/      legacy CICIDS2017 batch pipeline
src/features/       cleaning, preprocessing, transformation, validation
src/models/         batch training and evaluation (LR / DT / RF)
frontend/           React + TypeScript + Vite + Recharts dashboard
models/             zeek/ live model, best_model.joblib batch model
reports/            evaluation reports, threshold sweep, model card
scripts/            run_api.sh, zeek_live.sh, replay_zeek_holdout.py
tests/              85 tests (parser, features, store, reader, detectors, API)
docs/               PROJECT_ARCHITECTURE.md
```

## Configuration

All runtime settings are environment variables (see `src/realtime/config.py`):
`NDR_ZEEK_LOG_DIR`, `NDR_DB_PATH`, `NDR_MODEL_PATH`, `NDR_SENSOR_ID`, `NDR_SENSOR_MODE`,
`NDR_POLL_INTERVAL`, `NDR_INGEST_ENABLED`, `NDR_CORS_ORIGINS`, `NDR_RETENTION_DAYS`,
`NDR_FRONTEND_DIST`, `NDR_METRICS_WINDOW`, `NDR_WS_METRICS_INTERVAL`, `NDR_MAX_WS_CLIENTS`,
`NDR_WS_QUEUE_SIZE`, `NDR_API_HOST`, `NDR_API_PORT`, `NDR_API_KEY`.

`NDR_API_KEY` is optional and off by default. When set, every `/api/*` call except
`/api/health` must send it as `X-API-Key` (or `Authorization: Bearer`), and the WebSocket
must pass `?api_key=...`. The dashboard reads the same value from `VITE_API_KEY` at build
time.

## Known limitations

No live sensor validation in this environment; weak cross-dataset transfer; metadata-only
detection (no payload analysis); SQLite single-node storage; authentication is opt-in
(`NDR_API_KEY`) rather than enforced by default; heuristic detector thresholds that need
per-site tuning. The full list, with context, is in
[`docs/PROJECT_ARCHITECTURE.md`](docs/PROJECT_ARCHITECTURE.md#12-current-limitations).
