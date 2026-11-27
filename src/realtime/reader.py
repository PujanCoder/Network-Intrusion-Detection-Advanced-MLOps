"""Incremental, rotation-aware reader for Zeek log files.

Guarantees
----------
* Only complete lines are consumed; a line still being written by Zeek stays
  in a per-file buffer until its newline arrives.
* Offsets are persisted in SQLite, so a restart resumes exactly where the
  previous run stopped instead of replaying the whole log.
* Rotation (new inode) and truncation (size < offset) reset the offset to 0
  and are counted, so sensor monitoring can surface them.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from src.realtime.store import Store
from src.realtime.zeek_parser import NormalizedEvent, ZeekLogParser, log_type_for_path

logger = logging.getLogger(__name__)


@dataclass
class ReaderStats:
    rotations: int = 0
    truncations: int = 0
    unparsed_lines: int = 0
    files_tracked: int = 0
    last_file: str | None = None
    last_read_at: float | None = None


@dataclass
class FileState:
    inode: int
    offset: int
    pending: bytes = b""
    size: int = 0


class ZeekLogReader:
    def __init__(
        self,
        log_dir: str | Path,
        store: Store,
        sensor: str,
        parser: ZeekLogParser | None = None,
    ) -> None:
        self.log_dir = Path(log_dir)
        self.store = store
        self.sensor = sensor
        self.parser = parser or ZeekLogParser()
        self.stats = ReaderStats()
        self._states: dict[str, FileState] = {}

    # ------------------------------------------------------------------ #
    # discovery
    # ------------------------------------------------------------------ #
    def log_files(self) -> list[Path]:
        if not self.log_dir.exists():
            return []
        files = [
            path
            for path in self.log_dir.iterdir()
            if path.is_file() and path.suffix == ".log" and not path.name.startswith(".")
        ]
        return sorted(files, key=lambda p: (log_type_for_path(p) != "conn", p.name))

    def _initial_state(self, path: Path, size: int, inode: int) -> FileState:
        key = str(path)
        if key in self._states:
            return self._states[key]
        persisted = self.store.get_ingestion_state().get(key)
        offset = 0
        if persisted and persisted.get("inode") == inode and persisted.get("offset", 0) <= size:
            offset = int(persisted["offset"])
        elif persisted:
            # File was rotated or truncated while we were stopped.
            offset = 0
        state = FileState(inode=inode, offset=offset, pending=b"", size=size)
        self._states[key] = state
        return state

    # ------------------------------------------------------------------ #
    # reading
    # ------------------------------------------------------------------ #
    def read_new(self) -> Iterator[tuple[Path, int, NormalizedEvent]]:
        for path in self.log_files():
            try:
                stat = path.stat()
            except FileNotFoundError:
                continue

            state = self._initial_state(path, stat.st_size, stat.st_ino)

            if state.inode != stat.st_ino:
                self.stats.rotations += 1
                logger.info("Log rotation detected for %s", path.name)
                state = FileState(inode=stat.st_ino, offset=0, pending=b"", size=stat.st_size)
                self._states[str(path)] = state
            elif stat.st_size < state.offset:
                self.stats.truncations += 1
                logger.info("Log truncation detected for %s", path.name)
                state.offset = 0
                state.pending = b""

            if stat.st_size <= state.offset and not state.pending:
                continue

            try:
                with path.open("rb") as handle:
                    handle.seek(state.offset)
                    delta = handle.read()
            except OSError as error:
                logger.warning("Could not read %s: %s", path, error)
                continue

            if not delta:
                continue

            data = state.pending + delta
            if b"\n" not in data:
                # Keep the tail in memory and move the in-memory offset past the
                # bytes already read. The persisted offset stays at the last
                # complete line, so a restart re-reads this tail instead of
                # dropping it or duplicating it.
                state.pending = data
                state.offset = stat.st_size
                state.size = stat.st_size
                continue

            *complete, remainder = data.split(b"\n")
            consumed = len(data) - len(remainder)
            batch_start = state.offset
            state.pending = remainder
            state.offset += consumed
            state.size = stat.st_size
            self.stats.files_tracked = len(self._states)
            self.stats.last_file = path.name

            for raw_line in complete:
                line = raw_line.decode("utf-8", errors="replace")
                line_offset = batch_start
                batch_start += len(raw_line) + 1
                if not line.strip():
                    continue
                record = self.parser.parse_line(str(path), line)
                if record is None:
                    if not line.startswith("#"):
                        self.stats.unparsed_lines += 1
                    continue
                try:
                    event = self.parser.normalize(
                        record,
                        log_type_for_path(path),
                        self.sensor,
                        str(path),
                        line_offset,
                    )
                except Exception as error:  # pragma: no cover - defensive
                    logger.warning("Normalization failed in %s: %s", path.name, error)
                    self.stats.unparsed_lines += 1
                    continue
                if event is not None:
                    yield path, state.offset, event

            self.store.set_ingestion_state(str(path), state.inode, state.offset, stat.st_size)
            self.stats.last_read_at = stat.st_mtime

    def reset_offsets(self) -> None:
        """Forget in-memory state so the next poll re-reads from SQLite."""

        self._states.clear()

    def sensor_health(self) -> dict[str, object]:
        files = self.log_files()
        newest = max((path.stat().st_mtime for path in files), default=None)
        return {
            "log_dir": str(self.log_dir),
            "log_dir_exists": self.log_dir.exists(),
            "log_files": [path.name for path in files],
            "log_file_count": len(files),
            "newest_log_mtime": newest,
            "rotations": self.stats.rotations,
            "truncations": self.stats.truncations,
            "unparsed_lines": self.stats.unparsed_lines,
            "files_tracked": len(self._states),
            "pid": os.getpid(),
        }
