# Project Architecture — Advanced Real-Time Network Detection and Response (NDR) Platform

This document describes what the repository contains today, how the parts fit together,
and what has actually been verified. It supersedes the original CICIDS2017-only
description while keeping that pipeline documented, because it is still present and
still runs.

Status of the statements in this document:

- **Implemented and executed** — exercised in this workspace, with the observed output quoted.
- **Implemented, not executed here** — code and tests exist, but the environment (for example a
  live Zeek sensor) was not available, so it is not claimed as verified.

Nothing in this repository fabricates network events or predictions.

---

## 1. Project history in one paragraph

The project started as a batch machine-learning pipeline over the CICIDS2017 CSV dataset:
clean, split, transform, train Logistic Regression / Decision Tree / Random Forest, pick the
best model, and track the run in MLflow/DagsHub with DVC for data versioning. A second stage
added a real-time path: Zeek writes JSON logs, a Python reader tails them, events are normalised
and persisted in SQLite, a Zeek-compatible model scores each flow, and FastAPI plus a web
dashboard present the result. This repository is the third stage: the real-time path was rebuilt
into an NDR platform (multi-dataset model, rule-based detectors, six dashboard pages, full test
suite, honest sensor telemetry) while the original batch pipeline was left intact.

---

## 2. Original CICIDS2017 architecture (still present)

```
data/raw/MachineLearningCSV/*.csv
        │
        ▼
src/pipelines/pipeline.py                    9 sequential stages
  1 DATA INGESTION          src/features/data_cleaning.load_dataset
  2 DATA CLEANING           src/features/data_cleaning.clean_dataset
  3 DATA SPLITTING          src/features/data_preprocessing.split_data
  4 OUTLIER HANDLING        src/features/feature_transformation
  5 DRIFT VALIDATION        src/features/transformation_validation (Evidently)
  6 FEATURE TRANSFORMATION  scaling / encoding -> data/processed/transformed
  7 TRANSFORMATION CHECK    schema + distribution assertions
  8 MODEL TRAINING          src/models/train_model.py  (LR / DT / RF)
  9 MODEL EVALUATION        src/models/evaluate_model.py
        │
        ├── models/best_model.joblib            best batch classifier
        ├── reports/training_results.json       metrics for all candidates
        ├── reports/model_evaluation/*          comparison table + results
        ├── reports/data_drift_report.html      Evidently drift report
        └── MLflow / DagsHub run (params.yaml -> experiment_name)
```

Versioning and automation around the batch pipeline:

| Component | File | Role |
|---|---|---|
| DVC pipeline | `dvc.yaml`, `dvc.lock` | `ml_pipeline` stage: data → processed artefacts → `models/best_model.joblib` |
| DVC model stage | `dvc.yaml` | `model_training` stage: `src/models/train_model.py` from `params.yaml` |
| Parameters | `params.yaml` | dataset paths, test size, per-algorithm hyper-parameters, MLflow names |
| Experiment tracking | `src/models/train_model.py` | MLflow runs, optional DagsHub remote |
| CI | `.github/workflows/ci.yml` | dependency install, compile check, pytest |
| CD | `.github/workflows/cd.yml` | `dvc pull` of the raw dataset, then full pipeline |
| MongoDB ingestion (legacy) | `src/database/mongodb.py`, `src/ingestion/ingest_to_mongodb.py` | earlier CSV → MongoDB loader, superseded by SQLite for the real-time path but kept |

The batch model is **not** used by the live dashboard. It is exposed read-only through
`GET /api/model` under `batch_model` so the two model families stay clearly separated.

---

## 3. Real-time NDR architecture (current)

```
   ┌───────────────────────────────┐
   │ Network traffic (live or PCAP)│
   └───────────────┬───────────────┘
                   ▼
   ┌───────────────────────────────┐
   │ Zeek sensor                   │  scripts/zeek_live.sh
   │ conn.log (TSV or JSON)        │  Zeek 6+ / 7.x, tab-separated or @fields JSON
   └───────────────┬───────────────┘
                   ▼  append-only log file
   ┌───────────────────────────────┐
   │ src/realtime/reader.py        │  byte-offset tail, inode watch,
   │ incremental log reader        │  partial-line buffering, rotation + truncation
   └───────────────┬───────────────┘
                   ▼
   ┌───────────────────────────────┐
   │ src/realtime/zeek_parser.py   │  TSV header parsing, JSON records,
   │ normalisation                 │  Zeek type coercion, stable event UID
   └───────────────┬───────────────┘
                   ▼
   ┌───────────────────────────────┐
   │ src/realtime/features.py      │  23 flow features shared by
   │ feature extraction            │  training and inference
   └──────┬────────────────┬───────┘
          ▼                ▼
 ┌─────────────────┐  ┌──────────────────────────┐
 │ model.py        │  │ detectors.py             │
 │ HistGradient-   │  │ 10 behavioural rules     │
 │ Boosting        │  │ (scan, flood, brute      │
 │ classifier      │  │  force, beacon, exfil…)  │
 └────────┬────────┘  └───────────┬──────────────┘
          └───────────┬───────────┘
                      ▼
   ┌───────────────────────────────┐
   │ src/realtime/store.py         │  SQLite (WAL): events, predictions,
   │ persistence                   │  alerts, ingestion_state, dead_letters
   └───────────────┬───────────────┘
                   ▼
   ┌───────────────────────────────┐
   │ src/realtime/broadcast.py     │  asyncio fan-out, bounded queues,
   │ WebSocket hub                 │  thread-safe publish from the reader thread
   └───────────────┬───────────────┘
                   ▼
   ┌───────────────────────────────┐
   │ FastAPI (src/api/*)           │  REST + /api/ws + static dashboard
   └───────────────┬───────────────┘
                   ▼
   ┌───────────────────────────────┐
   │ React dashboard (frontend/)   │  Overview, Stream, Analytics, Attacks,
   │ 6 pages, live WS updates      │  Model, Explorer, Sensors
   └───────────────────────────────┘
```

### 3.1 Threading model

`IngestionService` owns a daemon thread that polls the log directory every
`NDR_POLL_INTERVAL` seconds (default 0.5 s). For each new line it:

1. parses and normalises the record,
2. computes the feature vector,
3. asks the detector engine for rule hits,
4. asks the model for a prediction (skipped when the log type is not `conn`),
5. writes event → prediction → alerts inside one SQLite transaction,
6. publishes `{"type": "event", ...}` through the WebSocket hub.

The hub is bound to the uvicorn event loop, so `publish_threadsafe` schedules the broadcast
on that loop. A slow or disconnected client is dropped after `NDR_WS_QUEUE_SIZE` backlog
messages rather than blocking ingestion.

A separate asyncio task (`_metrics_ticker`) pushes `{"type": "metrics", ...}` once per
second, derived from SQLite aggregates — the dashboard never invents numbers.

---

## 4. Directory structure

```
Network-Intrusion-Detection-Advanced-MLOps/
├── src/
│   ├── api/
│   │   ├── app.py                 FastAPI factory, lifespan, WS hub, metrics ticker
│   │   ├── routes.py              REST endpoints, CSV export, /api/ws
│   │   └── predictor.py           ModelService: loads the Zeek model, wraps prediction
│   ├── realtime/
│   │   ├── config.py              Settings dataclass, NDR_* environment variables
│   │   ├── zeek_parser.py         TSV/JSON parsing + NormalizedEvent
│   │   ├── reader.py              incremental tail of Zeek logs
│   │   ├── features.py            23-feature extractor (shared train/inference)
│   │   ├── model.py               FlowClassifier: scoring + explanations
│   │   ├── detectors.py           DetectorEngine with 10 behavioural rules
│   │   ├── store.py               SQLite schema, queries, aggregates
│   │   ├── service.py             ingestion loop, counters, sensor status
│   │   ├── broadcast.py           ConnectionManager (WebSocket fan-out)
│   │   ├── datasets.py            CICIDS2017 / UNSW-NB15 / NSL-KDD loaders
│   │   └── training.py            training, threshold tuning, evaluation, model card
│   ├── pipelines/pipeline.py      legacy CICIDS2017 batch pipeline (9 stages)
│   ├── features/                  cleaning, preprocessing, transformation, validation
│   ├── models/                    train_model.py, evaluate_model.py (LR/DT/RF)
│   ├── data/profile_dataset.py    dataset profiling
│   ├── database/, ingestion/      legacy MongoDB path
│   └── __init__.py
├── frontend/                      React + TypeScript + Vite + Recharts dashboard
│   ├── src/pages/                 Overview, Stream, Analytics, Attacks, Model,
│   │                              Explorer, Sensors
│   ├── src/components/            Layout, EventTable, EventDrawer, Charts, ui
│   ├── src/hooks/useLiveStream.ts REST bootstrap + WebSocket subscription
│   └── dist/                      production build served by FastAPI
├── models/
│   ├── best_model.joblib          batch CICIDS2017 model (legacy pipeline output)
│   └── zeek/                      zeek_model.joblib + metadata JSON (live model)
├── data/
│   ├── raw/                       CICIDS2017 CSV
│   ├── external/                  unsw-nb15/, nsl-kdd/
│   ├── processed/, interim/       batch pipeline artefacts
│   ├── zeek_logs/                 Zeek conn.log (sensor output)
│   └── realtime/ndr.db            SQLite database
├── reports/
│   ├── zeek_model/                evaluation.json, threshold_analysis.csv,
│   │                              false_positives.csv, false_negatives.csv,
│   │                              model_card.md
│   ├── training_results.json      batch metrics
│   └── model_evaluation/          batch comparison
├── scripts/
│   ├── run_api.sh                 uvicorn + built dashboard
│   ├── zeek_live.sh               Zeek on an interface → data/zeek_logs/conn.log
│   └── replay_zeek_holdout.py     replay held-out flows into conn.log
├── tests/                         85 tests (unit + API + WebSocket)
├── docs/PROJECT_ARCHITECTURE.md   this file
├── dvc.yaml / dvc.lock            batch pipeline stages
├── params.yaml                    batch hyper-parameters
├── requirements.txt               Python dependencies (UTF-8)
└── .github/workflows/             ci.yml, cd.yml
```

---

## 5. Module reference

### 5.1 `src/realtime/config.py`

Frozen dataclass `Settings` plus `get_settings()` (cached). Every field has an environment
variable, so containers and CI need no code changes.

| Variable | Default | Meaning |
|---|---|---|
| `NDR_ZEEK_LOG_DIR` | `data/zeek_logs` | directory watched for `conn.log`, `dns.log`, … |
| `NDR_DB_PATH` | `data/realtime/ndr.db` | SQLite file |
| `NDR_MODEL_PATH` | `models/zeek/zeek_model.joblib` | live classifier |
| `NDR_SENSOR_ID` | `zeek-sensor-01` | sensor identity stored on each event |
| `NDR_SENSOR_MODE` | `live` | `live` / `replay` / `pcap` label |
| `NDR_POLL_INTERVAL` | `0.5` | log poll interval, seconds |
| `NDR_INGEST_ENABLED` | `true` | start the reader thread |
| `NDR_CORS_ORIGINS` | `http://localhost:5173,…` | dev-server origins |
| `NDR_RETENTION_DAYS` | `7` | pruning horizon for old rows |
| `NDR_FRONTEND_DIST` | `frontend/dist` | static dashboard root |
| `NDR_METRICS_WINDOW` | `300` | rolling window for rates |
| `NDR_WS_METRICS_INTERVAL` | `1.0` | metrics push interval |
| `NDR_MAX_WS_CLIENTS`, `NDR_WS_QUEUE_SIZE` | `200`, `500` | hub limits |
| `NDR_API_HOST`, `NDR_API_PORT` | `0.0.0.0`, `8000` | bind address |

### 5.2 `src/realtime/zeek_parser.py`

Accepts both Zeek output flavours:

- **TSV** with a `#separator \x09` / `#fields …` header block (Zeek default), and
- **JSON** one-object-per-line (`ZeekJsonLog` / `json-streaming` writer).

`NormalizedEvent` carries the flow tuple (addresses, ports, proto, service, conn_state),
volumetrics (duration, bytes, packets), the raw record, and a stable `event_uid` of the form
`<sensor>:<log_type>:<zeek_uid>` (falling back to a content hash when Zeek supplies no `uid`).
Because the UID is derived from Zeek's own flow identifier and not from the file offset,
re-reading the same line after a restart cannot create a duplicate.

### 5.3 `src/realtime/reader.py`

Tails each file in the log directory using persisted byte offsets (`ingestion_state` table):

- new data → read from the stored offset;
- incomplete trailing line → kept in memory, offset advanced only in memory so a restart
  re-reads the tail instead of dropping or duplicating it;
- inode change → treated as rotation, offset reset to 0;
- file shorter than the stored offset → truncation, offset reset to 0.

Counters (`rotations`, `truncations`, `unparsed_lines`) are exposed in the sensor page.

### 5.4 `src/realtime/features.py`

One extractor (`features_from_zeek`) is used for both training and inference; there is no
second, divergent implementation. 23 features:

```
dst_port_class, duration_s, orig_bytes, resp_bytes, orig_pkts, resp_pkts,
orig_ip_bytes, resp_ip_bytes, fwd_pkt_len_mean, bwd_pkt_len_mean,
flow_bytes_per_s, flow_packets_per_s, down_up_ratio, avg_packet_size,
bytes_ratio, syn_flag, ack_flag, fin_flag, rst_flag, psh_flag, urg_flag,
conn_state_code, proto_code
```

`dst_port_class` groups the destination port into service classes (web, dns, mail, ssh, rdp,
database, high ephemeral, …) instead of using the raw port number. The raw port is
dataset-specific and would let a model memorise which ephemeral ports a particular capture
used; the class generalises across CICIDS2017, UNSW-NB15 and NSL-KDD and maps directly onto
fields Zeek always emits.

Derived rates use `duration` with a floor so a zero-duration flow does not produce infinity.

### 5.5 `src/realtime/model.py`

`FlowClassifier` loads the joblib artefact plus its metadata and exposes:

- `predict(features)` → label, malicious flag, confidence, malicious score, threshold,
  severity, explanation, latency in milliseconds;
- `info()` → everything the model page shows (schema, metrics, top features, environment);
- graceful degradation: when the artefact is missing the API still starts and reports
  `loaded: false` with the load error, and events are stored as unclassified.

Explanations are generated from the flow itself (byte counts, duration, packet rate, port
class, connection state) together with the global permutation importance of the features that
drove the score. They are descriptive, not SHAP attributions.

### 5.6 `src/realtime/detectors.py`

Rule engine evaluated on every `conn` event, independent of the ML model, so a signature-style
detection still fires when the model is unavailable:

| Rule | Intent |
|---|---|
| `port_scan_sweep` | one source hitting many destination ports on one host |
| `host_sweep` | one source touching many distinct hosts |
| `syn_flood` | SYN-heavy burst against a single service |
| `auth_brute_force` | repeated rejected connections to SSH/RDP/FTP/SMB |
| `c2_beaconing` | regular-interval connections to one destination |
| `outbound_exfiltration` | large outbound volume to an external address |
| `large_outbound_flow` | single very large upload |
| `connection_failure_ratio` | mostly-failed connection set from one source |
| `exposed_high_risk_service` | inbound traffic to Telnet/SMB/RDP/database ports |
| `dns_tunneling` | long, high-entropy DNS query names |

Each hit carries rule name, category, severity, confidence, human explanation and an evidence
dictionary. Alerts are de-duplicated per event and rule through a unique `dedupe_key`.

### 5.7 `src/realtime/store.py`

SQLite with WAL journaling, one connection per thread, `PRAGMA quick_check` for the health
endpoint. Tables:

| Table | Purpose | Key columns |
|---|---|---|
| `events` | normalised flow records | `event_uid UNIQUE`, `ts`, endpoints, proto, service, conn_state, volumes, `raw_json`, `ingested_at` |
| `predictions` | one row per scored event | `event_id`, `label`, `is_malicious`, `confidence`, `malicious_score`, `threshold`, `severity`, `explanation`, `latency_ms`, `error` |
| `alerts` | rule hits | `event_id`, `rule`, `category`, `severity`, `confidence`, `evidence_json`, `dedupe_key UNIQUE` |
| `ingestion_state` | reader offsets | `source_file`, `inode`, `offset`, `size`, `updated_at` |
| `dead_letters` | records that failed processing | `source_file`, `line_offset`, `payload`, `error` |
| `service_state` | last sensor status snapshot | key/value JSON |

Indexes cover `events.ts`, `events.src_ip`, `events.dst_ip`, `predictions.label`,
`predictions.created_at`, `alerts.severity`, `alerts.created_at`.

Duplicate protection is threefold: `events.event_uid UNIQUE` with `INSERT OR IGNORE`,
`predictions.event_id` uniqueness, and `alerts.dedupe_key UNIQUE`.

### 5.8 `src/realtime/service.py`

The ingestion loop and its telemetry. Counters: `lines_processed`, `events_inserted`,
`duplicates_skipped`, `predictions`, `unclassified`, `alerts`, `errors`, `replay_records`.
Failures never stop the loop: the record goes to `dead_letters`, the error is counted, and
processing continues.

### 5.9 `src/realtime/datasets.py` + `training.py`

Loaders for the three public datasets and the training/evaluation procedure (section 8).

### 5.10 `src/api/`

- `app.py` — `create_app()` builds the FastAPI instance, loads settings and the model, starts
  the ingestion thread and the metrics ticker in `lifespan`, mounts `frontend/dist` at `/`.
- `routes.py` — all REST endpoints and `/api/ws`.
- `predictor.py` — `ModelService`, the only place that talks to the model from the API side.

### 5.11 `frontend/`

React 19 + TypeScript + Vite + Recharts, hash routing, dark SOC-style theme.

| Page | Route | Content |
|---|---|---|
| Overview | `/` | KPI tiles, sensor card, model card, traffic mix, 15-minute rate chart, latest predictions |
| Live stream | `/stream` | auto-updating prediction table with severity colouring, pause control, row → detail drawer |
| Traffic analytics | `/analytics` | rates, volume, benign/suspicious mix, attack distribution, protocol mix, severity, top sources/destinations, confidence histogram |
| Attack monitoring | `/attacks` | ML attacks plus HIGH/CRITICAL rule alerts, severity filter, evidence panel |
| Model monitoring | `/model` | live model card, evaluation table, confusion matrix, feature schema, permutation importance, runtime behaviour |
| Event explorer | `/explorer` | search, protocol/prediction/severity filters, time range, pagination, JSON drawer, CSV export |
| Sensor health | `/sensors` | Zeek capture state, counters, event→DB delay, database/API/WebSocket status, detector list |

`useLiveStream` bootstraps from REST (`/api/overview`, `/api/sensors`, `/api/model`) and then
applies WebSocket `event` and `metrics` messages. When the socket drops it retries with
backoff and shows `reconnecting`; the header badge reflects the real socket state.

---

## 6. Data flow: from packet to pixel

1. **Capture** — Zeek writes a record to `conn.log` when a flow closes (or after its
   `Conn::default_extract` timeout). Fields used: `ts`, `uid`, `id.orig_h`, `id.orig_p`,
   `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`,
   `orig_pkts`, `resp_pkts`, `conn_state`, `history`.
2. **Read** — `ZeekLogReader` detects appended bytes, splits on newlines, keeps partial lines.
3. **Normalise** — `ZeekLogParser` converts Zeek's `-` placeholders to `None`, casts types and
   builds `NormalizedEvent` with a stable UID.
4. **Features** — `features_from_zeek` builds the 23-value vector.
5. **Detect** — `DetectorEngine.observe` returns rule hits with severity and evidence.
6. **Score** — `FlowClassifier.predict` returns label, malicious score, threshold, severity,
   explanation and the measured inference latency.
7. **Persist** — `Store` writes event, prediction and alerts; `ingested_at` records the write
   time, which is what the dashboard reports as event→database delay.
8. **Broadcast** — the hub queues `{"type": "event", "event": {...}}` for every client.
9. **Render** — the dashboard prepends the row, highlights malicious/suspicious flows, and
   refreshes KPI tiles from the per-second `metrics` message.

Latency is measured, not estimated: `latency_ms` is the wall time of the model call, and
`processing_delay()` reports `ingested_at - ts` over the last 200 events.

---

## 7. API architecture

Base path `/api`. All responses are JSON except the CSV export.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | liveness, version, uptime, DB integrity, ingestion flags |
| GET | `/api/overview` | KPI counters, rolling rates, model card summary, sensor state, WebSocket stats, `no_new_events` flag |
| GET | `/api/events` | paginated events with `search`, `proto`, `prediction`, `severity`, `start`, `end`, `malicious_only` |
| GET | `/api/events/export.csv` | same filters, streamed CSV (25 columns) |
| GET | `/api/events/{id}` | single event with prediction, alerts and original Zeek JSON |
| GET | `/api/attacks` | ML attacks and HIGH/CRITICAL rule alerts, severity + time filters |
| GET | `/api/analytics` | time series, distributions, top talkers, confidence histogram |
| GET | `/api/model` | `live_model` (Zeek) and `batch_model` (CICIDS2017) kept separate, plus runtime counters |
| GET | `/api/detections` | rule hit counts per rule and the detector catalogue |
| GET | `/api/sensors` | sensor block, ingestion offsets, DB/API/WS status, processing delay, dead letters |
| WS | `/api/ws` | live stream: `hello`, `event`, `metrics`, `ping` |

WebSocket contract:

```jsonc
// on connect
{"type": "hello", "server_time": 1795762162.1, "model": {...}, "sensor": {...}}
// per processed event (from the ingestion thread)
{"type": "event", "event": {"id": 812, "ts": ..., "src_ip": "...", "prediction": "DoS",
                            "confidence": 0.98, "severity": "CRITICAL", "alerts": [...],
                            "raw": {...}}}
// once per second, DB-derived
{"type": "metrics", "overview": {"total_events": 812, "events_per_second": 1.9, ...}}
```

---

## 8. Model architecture

### 8.1 Training data

| Dataset | Rows used | Role |
|---|---|---|
| CICIDS2017 (MachineLearningCSV) | 225,745 | primary flow-level source |
| UNSW-NB15 | 82,332 | second source, different capture tooling |
| NSL-KDD | 125,973 | third source, plus official `KDDTest+` partition |

Total 298,222 rows → stratified split **train 208,755 / validation 44,733 / test 44,734**.
The split is stratified by `(dataset, label)` so every class and every dataset appears in all
three partitions.

Leakage controls:

- one extractor for training and inference (no train-time-only transforms);
- no raw destination port, no timestamps, no dataset identifier, no file names;
- threshold tuned on the validation partition only;
- the test partition is scored once, after model selection;
- official test partitions of UNSW-NB15 and NSL-KDD are scored separately and never trained on;
- a cross-dataset probe retrains without NSL-KDD and evaluates on `KDDTest+` to quantify
  generalisation to an unseen dataset.

### 8.2 Algorithm and selection

Candidates: Logistic Regression, Decision Tree, Random Forest, HistGradientBoosting. Selection
is by validation macro-F1; `hist_gradient_boosting` won (0.568 validation macro-F1 versus
0.9994/0.9998/1.0000 *binary* accuracy of the batch-pipeline candidates on the much easier
single-dataset problem — the two numbers are not comparable and are displayed separately).

Operating threshold: **0.95**, chosen to meet a **5% false-positive budget** on validation.

### 8.3 Measured performance (current artefact `2026.11.27-37f7a80`)

| Partition | Rows | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| validation (all) | 44,733 | 0.9642 | 0.9806 | 0.9723 | 0.0343 |
| test (all) | 44,734 | 0.9629 | 0.9831 | 0.9729 | 0.0356 |
| UNSW-NB15 official test | 175,341 | 0.9410 | 0.9369 | 0.9390 | 0.1252 |
| NSL-KDD official test (`KDDTest+`) | 22,544 | 0.9431 | 0.4920 | 0.6467 | 0.0392 |
| per-dataset test — CICIDS2017 | — | 1.000 | 0.998 | 0.999 | — |
| per-dataset test — UNSW-NB15 | — | 0.721 | 0.873 | 0.790 | 0.187 |
| per-dataset test — NSL-KDD | — | 0.906 | — | 0.906 | — |

Zero-day probe (model retrained without NSL-KDD, scored on `KDDTest+`): recall 0.00% at
0.00% FPR with the threshold tuned on its own validation set. That is the honest answer: the
classifier does not transfer to a dataset it has never seen. It is displayed on the model page
with that explanation instead of being hidden.

### 8.4 Artefacts

- `models/zeek/zeek_model.joblib` — sklearn pipeline (scaler + classifier) plus metadata.
- `models/zeek/zeek_model_metadata.json` — schema, classes, threshold, all metrics, candidate
  scores, latency, environment, notes.
- `reports/zeek_model/evaluation.json` — full report of the last training run.
- `reports/zeek_model/threshold_analysis.csv` — precision/recall/FPR across thresholds.
- `reports/zeek_model/false_positives.csv`, `false_negatives.csv` — sampled errors for review.
- `reports/zeek_model/model_card.md` — human-readable model card with limitations.

---

## 9. MLOps workflow

```
params.yaml ─┐
             ├─► dvc.yaml : ml_pipeline        ─► data/processed, models/best_model.joblib,
raw CSV ─────┘                                    reports/training_results.json
             └─► dvc.yaml : model_training     ─► MLflow run (params + metrics + model)

python -m src.realtime.training                ─► models/zeek/*, reports/zeek_model/*
                                                  (multi-dataset live classifier)

GitHub Actions
  ci.yml : install → compile → pytest (85 tests) → frontend typecheck/build → docker build
  cd.yml : dvc pull → full batch pipeline
```

Reproducing the live model:

```bash
PYTHONPATH=$PWD python -m src.realtime.training --output-dir models/zeek
```

The command prints test precision/recall/F1 and the chosen threshold, and writes the metadata,
model card and error samples described above.

---

## 10. Running the platform

### 10.1 Backend + dashboard (single process)

```bash
python -m pip install -r requirements.txt
cd frontend && npm ci && npm run build && cd ..
PYTHONPATH=$PWD python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
# or: ./scripts/run_api.sh
```

Open <http://localhost:8000>. The dashboard is served from `frontend/dist`; the API lives
under `/api`.

### 10.2 Frontend development

```bash
cd frontend && npm install && npm run dev   # http://localhost:5173, proxied to :8000
```

### 10.3 Live Zeek capture

```bash
sudo ./scripts/zeek_live.sh -i eth0          # writes data/zeek_logs/conn.log
```

The script prints a warning if Zeek is not installed and exits non-zero rather than silently
pretending to capture.

### 10.4 Replay without a sensor

```bash
NDR_SENSOR_MODE=replay PYTHONPATH=$PWD python scripts/replay_zeek_holdout.py --rate 2 --loop
```

Replayed records carry `"_replay": true` in their raw JSON. The service counts them, the API
reports `sensor.mode = "replay"`, and both the overview and sensor pages display a
**Replay data detected** banner so a replay run can never be mistaken for live traffic.

### 10.5 Tests

```bash
PYTHONPATH=$PWD python -m pytest tests/ -q     # 75 passed
cd frontend && npx tsc --noEmit && npm run build
```

Test coverage: Zeek parsing (TSV + JSON + UID stability), feature extraction, SQLite store
(idempotency, filters, aggregates, alert de-duplication), log reader (partial lines, rotation,
truncation, duplicate UID), detectors (each rule plus cooldown suppression), and the API
(endpoints, filters, CSV export, WebSocket hello + event broadcast).

---

## 11. Verified end-to-end run in this workspace

Produced while validating this document: API on port 12000, dashboard built and opened in a
browser, replay harness writing `data/zeek_logs/conn.log` at ~2 records/s.

```
GET /api/health    -> status ok, sensor_mode replay, model_loaded true,
                      database integrity ok, journal_mode wal
GET /api/overview  -> total_events 1,780 · total_predictions 1,780 · attacks 916 ·
                      benign 864 · suspicious 0 · unclassified 0 ·
                      critical_detections 916 · avg_prediction_latency_ms 3.92 ·
                      events_per_second_live 2.0 · no_new_events false
GET /api/sensors   -> ingestion_running true · poll 0.5 s · rotations 0 · truncations 0 ·
                      unparsed_lines 0 · dead_letters 0 · duplicates_skipped 0 ·
                      errors 0 · counters.replay_records 1,804 ·
                      event->DB delay 1.34 s avg / 14.56 s max over 200 samples
GET /api/model     -> live zeek-flow-classifier 2026.11.27-37f7a80 · threshold 0.95 ·
                      predictions 1,804 · unclassified 0 · model_errors 0 ·
                      p50 2.97 ms · p95 ~10 ms
WebSocket          -> hello on connect, then event + metrics messages while ingesting
Dashboard          -> all six pages rendered live data with no visible failures
```

Idle behaviour was verified separately: with the replay stopped, `/api/overview` reported
`events_per_second_live 0.0`, `no_new_events true`, `seconds_since_last_event 20.0`, and the
Overview page displayed "No new network events received." The 5-minute average
(`events_per_second 1.87`) keeps decaying but is shown as a secondary figure so an idle sensor
is never presented as busy.

Earlier prototype figures (44 events, 29 predictions, 15 unclassified, 24 attacks) came from a
300-record synthetic model and are superseded by the run above. Both are recorded here because
the prototype numbers are still quoted in older notes.

## 12. Current limitations

1. **No live sensor in this environment.** Zeek was not installed in the container, so the
   pipeline was validated with replayed held-out flows, not a real interface. The code path is
   identical (`conn.log` in, events out), but "captured live traffic" is not claimed.
2. **Model transfer is weak.** `KDDTest+` recall is 49% and UNSW-NB15 FPR is 18.7% in-dataset;
   the zero-day probe scores 0% recall. The classifier is decision support, not a detector you
   can leave unattended.
3. **Feature approximation.** Zeek provides flow-level counters, not CICIDS2017's
   inter-arrival statistics; 23 features are the honest intersection, not a full mapping.
4. **Replay distribution is narrow.** The bundled replay file is attack-heavy (≈51% attacks,
   mostly DoS), so dashboard ratios from a replay run do not represent a real network.
5. **Single-node storage.** SQLite with WAL is fine for one sensor and tens of events/second;
   it is not a clustered store.
6. **No authentication.** The API and dashboard are unauthenticated. Do not expose them
   outside a trusted network without putting an authenticating proxy in front.
7. **Detector thresholds are heuristics.** Rules are tuned on synthetic and public traffic;
   they need per-site tuning and will produce false positives on unusual but benign behaviour.
8. **No packet payload analysis.** Detection is metadata-only (no DPI, no TLS fingerprinting,
   no file extraction).
9. **Retention is time-based only.** `NDR_RETENTION_DAYS` (default 7) triggers
   `purge_older_than` inside the ingestion loop, so old rows are deleted by age. There is no
   size cap, no archival tier and no compaction job.
10. **Frontend bundle size.** ~770 kB minified (Recharts). Acceptable for an internal tool,
    not optimised for slow links.

---

## 13. Roadmap

Near term

- Install Zeek in the deployment image and validate against a mirrored interface (SPAN port)
  with `tcpdump`-captured PCAPs as a control.
- Add PCAP → Zeek → pipeline regression tests so capture changes are caught in CI.
- Extend the feature set with Zeek `ssl.log`, `dns.log`, `http.log` and `notice.log` enrichment.
- Replace the heuristic beaconing/exfiltration thresholds with per-asset baselines.

Medium term

- Serve the model behind an inference queue so multiple sensors can share one scorer.
- Add authentication (OIDC) and role separation (viewer, analyst, admin).
- Add alert acknowledgement, suppression rules and per-asset allow-lists to cut false positives.
- Add retention jobs and database compaction.
- Add drift monitoring on the live feature distribution (Evidently is already a dependency).

Long term

- Stream processing (Kafka/Redpanda) instead of file tailing, with Zeek in cluster mode.
- Graph-based lateral-movement detection over the asset inventory.
- Analyst feedback loop that turns confirmed/false alerts into labelled data for retraining.
- Multi-tenant sensor fleet with central model registry and staged rollouts.
