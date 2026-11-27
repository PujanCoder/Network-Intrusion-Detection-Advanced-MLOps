# Advanced Real-Time Network Detection and Response (NDR) Platform
2
3A Zeek-driven network detection platform with a multi-dataset flow classifier, rule-based
4detectors, a FastAPI backend and a live security dashboard — built on top of the original
5CICIDS2017 intrusion-detection ML pipeline, which is still in the repository and still runs.
6
7> **Read this before trusting a number.** The live classifier is trained on public datasets
8> (CICIDS2017, UNSW-NB15, NSL-KDD). Its in-distribution scores are strong, its cross-dataset
9> transfer is weak (0% recall on an unseen dataset in the zero-day probe), and the API has no
10> authentication. It is a decision-support tool, not an unattended production sensor.
11
12---
13
14## What works today
15
16| Capability | State |
17|---|---|
18| Zeek `conn.log` ingestion (TSV and JSON) | Implemented, tested |
19| Incremental tailing with rotation / truncation / partial-line handling | Implemented, tested |
20| SQLite persistence with duplicate protection | Implemented, tested |
21| 23-feature extractor shared by training and inference | Implemented, tested |
22| Multi-dataset model training + evaluation + model card | Executed (`models/zeek`, `reports/zeek_model`) |
23| 10 rule-based behavioural detectors | Implemented, tested |
24| FastAPI REST + WebSocket API | Implemented, tested, executed |
25| React dashboard, 6 pages, live updates | Built, executed in a browser |
26| 75 automated tests | Passing |
27| Batch CICIDS2017 pipeline (MLflow/DagsHub/DVC) | Preserved |
28| Live Zeek capture on a real interface | **Not verified here** (no Zeek in this container) |
29
30Full detail: [`docs/PROJECT_ARCHITECTURE.md`](docs/PROJECT_ARCHITECTURE.md).
31
32---
33
34## Quick start
35
36```bash
37python -m pip install -r requirements.txt      # note: requirements.txt is UTF-16 encoded
38
39cd frontend && npm ci && npm run build && cd ..
40
41PYTHONPATH=$PWD python -m uvicorn src.api.app:app --host 0.0.0.0 --port 8000
42```
43
44Open <http://localhost:8000>. The dashboard is served from `frontend/dist`; the API is under
45`/api`.
46
47Frontend development with hot reload:
48
49```bash
50cd frontend && npm install && npm run dev     # http://localhost:5173
51```
52
53### Feed it traffic
54
55Real Zeek sensor (needs Zeek and an interface):
56
57```bash
58sudo ./scripts/zeek_live.sh -i eth0
59```
60
61Replay without a sensor:
62
63```bash
64NDR_SENSOR_MODE=replay PYTHONPATH=$PWD python scripts/replay_zeek_holdout.py --rate 2 --loop
65```
66
67Replayed records are tagged `"_replay": true`. The API reports `sensor.mode = "replay"` and the
68dashboard shows a **Replay data detected** banner — a replay can never be mistaken for live
69capture. With no traffic arriving the dashboard says **"No new network events received."**
70instead of inventing activity.
71
72### Tests
73
74```bash
75PYTHONPATH=$PWD python -m pytest tests/ -q      # 75 passed
76cd frontend && npx tsc --noEmit && npm run build
77```
78
79---
80
81## Architecture at a glance
82
83```
84Zeek conn.log ──► reader.py ──► zeek_parser.py ──► features.py ──┬──► model.py (HGB classifier)
85                                                                 └──► detectors.py (10 rules)
86                                        │
87                                        ▼
88                                   store.py (SQLite: events, predictions, alerts,
89                                             ingestion_state, dead_letters, service_state)
90                                        │
91                                        ▼
92                        broadcast.py (WebSocket fan-out) ──► FastAPI ──► React dashboard
93```
94
95- **Ingestion** — one daemon thread polls the log directory every 0.5 s, reads only new bytes,
96  and persists offsets so a restart resumes exactly where it stopped.
97- **Detection** — the model scores `conn` flows; rule detectors run independently and add
98  severity, category and evidence. Alerts are de-duplicated per event and rule.
99- **Serving** — REST for history and aggregates, WebSocket for live events and per-second
100  metrics. Every number shown comes from SQLite.
101- **Honesty** — measured inference latency, measured event→database delay, explicit
102  `no_new_events` flag, and a replay banner.
103
104---
105
106## Model
107
108| | |
109|---|---|
110| Artefact | `models/zeek/zeek_model.joblib` (+ metadata JSON) |
111| Version | `2026.11.27-37f7a80` |
112| Algorithm | HistGradientBoosting, operating threshold 0.95 (5% FPR budget) |
113| Training data | CICIDS2017 225,745 · UNSW-NB15 82,332 · NSL-KDD 125,973 |
114| Split | train 208,755 / validation 44,733 / test 44,734, stratified by (dataset, label) |
115| Test (all) | precision 0.963 · recall 0.983 · F1 0.973 · FPR 0.0356 |
116| UNSW-NB15 official test | precision 0.941 · recall 0.937 · F1 0.939 · FPR 0.125 |
117| NSL-KDD official test | precision 0.943 · recall 0.492 · F1 0.647 · FPR 0.039 |
118| Zero-day probe (trained without NSL-KDD) | recall 0.00 at 0.00 FPR — does not transfer |
119| Inference latency | p50 3.1 ms, p95 10.0 ms (measured) |
120
121Retrain:
122
123```bash
124PYTHONPATH=$PWD python -m src.realtime.training --output-dir models/zeek
125```
126
127Outputs: model + metadata, `reports/zeek_model/evaluation.json`, threshold sweep, sampled
128false positives/negatives, and `model_card.md`.
129
130The original batch model (`models/best_model.joblib`, Logistic Regression / Decision Tree /
131Random Forest on CICIDS2017) is untouched and is reported separately by `GET /api/model` under
132`batch_model`.
133
134---
135
136## API
137
138| Method | Path | Purpose |
139|---|---|---|
140| GET | `/api/health` | liveness, uptime, DB integrity, ingestion flags |
141| GET | `/api/overview` | KPI counters, rolling rates, model and sensor summary |
142| GET | `/api/events` | filters: `search`, `proto`, `prediction`, `severity`, `start`, `end`, `malicious_only` |
143| GET | `/api/events/export.csv` | same filters, streamed CSV |
144| GET | `/api/events/{id}` | full record, prediction, alerts, original Zeek JSON |
145| GET | `/api/attacks` | ML attacks + HIGH/CRITICAL rule alerts |
146| GET | `/api/analytics` | time series, distributions, top talkers, confidence histogram |
147| GET | `/api/model` | live model vs batch model, runtime counters |
148| GET | `/api/detections` | rule hit counts and detector catalogue |
149| GET | `/api/sensors` | sensor state, ingestion offsets, DB/API/WS status, processing delay |
150| WS | `/api/ws` | `hello`, `event`, `metrics`, `ping` |
151
152---
153
154## Dashboard
155
156| Page | What it shows |
157|---|---|
158| Overview | sensor/model status, total events, events and predictions per second, attacks, benign, suspicious, unclassified, critical alerts, traffic mix, 15-minute rate chart, latest predictions |
159| Live stream | continuously updating table (timestamp, endpoints, ports, proto, state, prediction, confidence, severity, explanation), malicious rows highlighted |
160| Traffic analytics | rates, volume, benign vs attack mix, attack classes, protocol mix, severity, top sources and destinations, confidence histogram |
161| Attack monitoring | detections with timestamps, endpoints, category, severity, confidence, evidence, history |
162| Model monitoring | active model, version, training data, feature schema, evaluation table, confusion matrix, importance, latency, unclassified count |
163| Event explorer | IP/protocol/prediction/severity/time filters, pagination, JSON drawer, CSV export |
164| Sensor health | Zeek capture state, counters, event→DB delay, database/API/WebSocket status, detector list |
165
166---
167
168## Repository layout
169
170```
171src/api/            FastAPI app, routes, model service
172src/realtime/       Zeek parsing, reader, features, model, detectors, store, service, training
173src/pipelines/      legacy CICIDS2017 batch pipeline
174src/features/       cleaning, preprocessing, transformation, validation
175src/models/         batch training and evaluation (LR / DT / RF)
176frontend/           React + TypeScript + Vite + Recharts dashboard
177models/             zeek/ live model, best_model.joblib batch model
178reports/            evaluation reports, threshold sweep, model card
179scripts/            run_api.sh, zeek_live.sh, replay_zeek_holdout.py
180tests/              75 tests (parser, features, store, reader, detectors, API)
181docs/               PROJECT_ARCHITECTURE.md
182```
183
184## Configuration
185
186All runtime settings are environment variables (see `src/realtime/config.py`):
187`NDR_ZEEK_LOG_DIR`, `NDR_DB_PATH`, `NDR_MODEL_PATH`, `NDR_SENSOR_ID`, `NDR_SENSOR_MODE`,
188`NDR_POLL_INTERVAL`, `NDR_INGEST_ENABLED`, `NDR_CORS_ORIGINS`, `NDR_RETENTION_DAYS`,
189`NDR_FRONTEND_DIST`, `NDR_METRICS_WINDOW`, `NDR_WS_METRICS_INTERVAL`, `NDR_MAX_WS_CLIENTS`,
190`NDR_WS_QUEUE_SIZE`, `NDR_API_HOST`, `NDR_API_PORT`.
191
192## Known limitations
193
194No live sensor validation in this environment; weak cross-dataset transfer; metadata-only
195detection (no payload analysis); SQLite single-node storage; no authentication; heuristic
196detector thresholds that need per-site tuning. The full list, with context, is in
197[`docs/PROJECT_ARCHITECTURE.md`](docs/PROJECT_ARCHITECTURE.md#12-current-limitations).
198
