# AGENTS.md

Repository notes for automated agents and contributors.

## Environment

- Python 3.13 at `/usr/local/bin/python`; run everything from the repository root.
- `requirements.txt` is UTF-16 encoded (CRLF). Edit it with `read_bytes().decode("utf-16")`
  and write it back with `.encode("utf-16")`, otherwise `read_text()` fails on the BOM.
- Frontend: Node 22+ / npm, Vite, React 19, TypeScript, Recharts.

## Commands

```bash
# tests (75)
PYTHONPATH=$PWD python -m pytest tests/ -q

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
- Detection results are decision support: in-distribution F1 ≈ 0.97, but cross-dataset
  transfer is weak and the zero-day probe scores 0 recall. Do not describe the model as
  production-ready.
