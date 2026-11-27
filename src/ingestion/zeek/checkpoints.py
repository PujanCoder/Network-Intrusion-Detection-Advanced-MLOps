from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class Checkpoint:
    source_file: str
    inode: str | None
    offset: int
    size: int
    mtime_ns: int
    last_event_ts: str | None
    status: str
    updated_at: str


CHECKPOINT_SCHEMA = """
CREATE TABLE IF NOT EXISTS zeek_ingestion_checkpoints (
    source_file TEXT PRIMARY KEY,
    inode TEXT,
    offset INTEGER NOT NULL DEFAULT 0,
    size INTEGER NOT NULL DEFAULT 0,
    mtime_ns INTEGER NOT NULL DEFAULT 0,
    last_event_ts TEXT,
    status TEXT NOT NULL DEFAULT 'ok',
    updated_at TEXT NOT NULL
);
"""


class CheckpointStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute(CHECKPOINT_SCHEMA)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path, isolation_level=None, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        return c

    def get(self, source_file: str) -> Checkpoint | None:
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM zeek_ingestion_checkpoints WHERE source_file=?",
                (source_file,),
            ).fetchone()
        if not row:
            return None
        return Checkpoint(**dict(row))

    def upsert(
        self,
        *,
        source_file: str,
        inode: str | None,
        offset: int,
        size: int,
        mtime_ns: int,
        last_event_ts: str | None,
        status: str = "ok",
    ) -> None:
        updated_at = datetime.now(timezone.utc).isoformat()
        with self._conn() as c:
            c.execute(
                """
                INSERT INTO zeek_ingestion_checkpoints
                (source_file, inode, offset, size, mtime_ns, last_event_ts, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_file) DO UPDATE SET
                    inode=excluded.inode,
                    offset=excluded.offset,
                    size=excluded.size,
                    mtime_ns=excluded.mtime_ns,
                    last_event_ts=excluded.last_event_ts,
                    status=excluded.status,
                    updated_at=excluded.updated_at
                """,
                (source_file, inode, offset, size, mtime_ns, last_event_ts, status, updated_at),
            )
