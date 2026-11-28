import json, sqlite3, threading
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER, proto TEXT,
    label TEXT NOT NULL, is_attack INTEGER NOT NULL,
    confidence REAL, proba_attack REAL,
    flow_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ts ON detections(ts);
CREATE INDEX IF NOT EXISTS idx_attack ON detections(is_attack, ts);
"""

class DetectionStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    def _conn(self):
        c = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def insert(self, flow: dict, pred: dict) -> int:
        with self._lock, self._conn() as c:
            cursor = c.execute(
                "INSERT INTO detections (ts, src_ip, dst_ip, src_port, dst_port, proto, "
                "label, is_attack, confidence, proba_attack, flow_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    flow.get("src_ip"), flow.get("dst_ip"),
                    flow.get("src_port"), flow.get("dst_port"),
                    flow.get("protocol") or flow.get("proto"),
                    pred["label"], int(pred["is_attack"]),
                    pred.get("confidence"), pred.get("proba_attack"),
                    json.dumps(flow, default=str),
                ),
            )
            return int(cursor.lastrowid or 0)

    def recent(self, limit: int = 100, only_attacks: bool = False) -> list[dict]:
        q = "SELECT * FROM detections"
        if only_attacks:
            q += " WHERE is_attack = 1"
        q += " ORDER BY id DESC LIMIT ?"
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, (limit,))]