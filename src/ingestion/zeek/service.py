from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Iterable

from src.serving.zeek_store import ZeekStore

from .checkpoints import CheckpointStore
from .normalizers.base import detect_log_type, normalize_record
from .parser import parse_zeek_json_line
from .tailer import FileTailer

log = logging.getLogger(__name__)

DEFAULT_LOG_TYPES = ["conn", "dns", "http", "ssl", "files", "notice"]
LOG_ALIASES = {"tls": "ssl"}


def _normalize_log_types(log_types: Iterable[str] | str | None) -> list[str]:
    if log_types is None:
        return list(DEFAULT_LOG_TYPES)
    if isinstance(log_types, str):
        items = [x.strip().lower() for x in log_types.split(",") if x.strip()]
    else:
        items = [str(x).strip().lower() for x in log_types if str(x).strip()]
    out: list[str] = []
    for it in items:
        it = LOG_ALIASES.get(it, it)
        if it not in out:
            out.append(it)
    return out or list(DEFAULT_LOG_TYPES)


class ZeekIngestionService:
    def __init__(
        self,
        *,
        db_path: Path,
        log_dir: Path,
        sensor_id: str = "local-sensor",
        log_types: Iterable[str] | str | None = None,
        poll_interval: float = 1.0,
    ):
        self.db_path = Path(db_path)
        self.log_dir = Path(log_dir)
        self.sensor_id = sensor_id
        self.log_types = _normalize_log_types(log_types)
        self.poll_interval = poll_interval
        self.store = ZeekStore(self.db_path)
        self.checkpoints = CheckpointStore(self.db_path)
        self.tailer = FileTailer(self.checkpoints)
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None

    def discover_log_files(self) -> list[Path]:
        if not self.log_dir.exists():
            return []
        files: list[Path] = []
        for lt in self.log_types:
            # Support .log and .log.gz? no, MVP JSON lines only
            p = self.log_dir / f"{lt}.log"
            if p.exists():
                files.append(p)
            # Zeek sometimes names ssl as tls.log
            if lt == "ssl":
                p2 = self.log_dir / "tls.log"
                if p2.exists() and p2 not in files:
                    files.append(p2)
        # Also pick up any known log type files with other naming in dir
        for p in sorted(self.log_dir.glob("*.log")):
            lt = detect_log_type(str(p), {})
            if lt in self.log_types and p not in files:
                files.append(p)
        return files

    def ingest_file_once(self, path: Path) -> dict[str, int]:
        counts = {"inserted": 0, "duplicate": 0, "dead_letter": 0, "lines": 0, "scored": 0, "unclassified": 0}
        for tl in self.tailer.read_new_lines(path):
            counts["lines"] += 1
            parsed = parse_zeek_json_line(tl.line)
            if not parsed.ok or parsed.record is None:
                self.store.insert_dead_letter(
                    sensor_id=self.sensor_id,
                    source_file=tl.source_file,
                    source_offset=tl.offset,
                    source_inode=tl.inode,
                    error=parsed.error or "parse error",
                    raw_line=tl.line,
                )
                counts["dead_letter"] += 1
                continue
            try:
                env = normalize_record(
                    record=parsed.record,
                    source_file=tl.source_file,
                    source_offset=tl.offset,
                    source_inode=tl.inode,
                    sensor_id=self.sensor_id,
                )
                event_dict = env.model_dump()
                inserted = self.store.insert_event(event_dict)
                counts["inserted" if inserted else "duplicate"] += 1

                # Score only newly inserted events to keep idempotent behavior clear.
                if inserted:
                    prediction = self._score_event(event_dict)
                    self.store.insert_detection(event_dict, prediction)
                    if prediction.get("status") == "scored":
                        counts["scored"] += 1
                    else:
                        counts["unclassified"] += 1
            except Exception as e:  # noqa: BLE001
                log.exception("failed to normalize/store zeek line: %s", e)
                self.store.insert_dead_letter(
                    sensor_id=self.sensor_id,
                    source_file=tl.source_file,
                    source_offset=tl.offset,
                    source_inode=tl.inode,
                    error=f"normalize/store error: {e}",
                    raw_line=tl.line,
                )
                counts["dead_letter"] += 1
        self.tailer.mark_status(path, "ok")
        return counts

    def _score_event(self, event: dict) -> dict:
        try:
            from src.serving.zeek_predictor import predict_zeek_event

            # The predictor needs the whole envelope: dst_port/proto live at the
            # top level, the volume counters inside "normalized".
            return predict_zeek_event(event)
        except Exception as e:  # noqa: BLE001
            log.exception("zeek scoring failed: %s", e)
            return {
                "label": "UNCLASSIFIED",
                "status": "unscored",
                "reason": f"scoring error: {e}",
                "is_attack": False,
                "confidence": None,
                "probabilities": None,
                "schema_version": None,
            }

    def status(self) -> dict[str, Any]:
        """Live state for the API's status endpoint and the dashboard."""

        return {
            "enabled": True,
            "running": bool(self._task and not self._task.done()),
            "log_dir": str(self.log_dir),
            "log_dir_exists": self.log_dir.exists(),
            "log_file_count": len(self.discover_log_files()),
            "sensor_id": self.sensor_id,
            "log_types": list(self.log_types),
            "poll_interval_s": self.poll_interval,
        }

    def ingest_once(self) -> dict[str, int]:
        totals = {"inserted": 0, "duplicate": 0, "dead_letter": 0, "lines": 0, "files": 0, "scored": 0, "unclassified": 0}
        for path in self.discover_log_files():
            try:
                c = self.ingest_file_once(path)
                for k in ["inserted", "duplicate", "dead_letter", "lines", "scored", "unclassified"]:
                    totals[k] += c.get(k, 0)
                totals["files"] += 1
            except Exception as e:  # noqa: BLE001
                log.exception("failed ingesting %s: %s", path, e)
                self.tailer.mark_status(path, f"error: {e}")
        return totals

    async def run_forever(self) -> None:
        log.info("zeek ingestion started: dir=%s sensor=%s types=%s", self.log_dir, self.sensor_id, self.log_types)
        while not self._stop.is_set():
            try:
                self.ingest_once()
            except Exception as e:  # noqa: BLE001
                log.exception("zeek ingestion loop error: %s", e)
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_interval)
            except asyncio.TimeoutError:
                pass
        log.info("zeek ingestion stopped")

    def start_background(self) -> None:
        if self._task and not self._task.done():
            return
        self._stop.clear()
        try:
            loop = asyncio.get_running_loop()
            self._task = loop.create_task(self.run_forever(), name="zeek-ingestion")
        except RuntimeError:
            # No running loop; caller should manage execution.
            pass

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
