from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .checkpoints import CheckpointStore


@dataclass
class TailedLine:
    line: str
    offset: int  # byte offset at start of line
    source_file: str
    inode: str | None


def _file_inode(path: Path) -> str | None:
    try:
        st = path.stat()
        # Windows st_ino may be 0; include size/mtime fallback in identity string.
        return f"{getattr(st, 'st_ino', 0)}:{getattr(st, 'st_dev', 0)}"
    except OSError:
        return None


class FileTailer:
    def __init__(self, checkpoint_store: CheckpointStore):
        self.checkpoints = checkpoint_store

    def read_new_lines(self, path: Path) -> Iterator[TailedLine]:
        path = Path(path)
        if not path.exists() or not path.is_file():
            return
            yield  # pragma: no cover

        st = path.stat()
        inode = _file_inode(path)
        cp = self.checkpoints.get(str(path))
        offset = 0
        if cp:
            # Rotation/truncation detection: if inode changed or file shrank, restart.
            if (cp.inode and inode and cp.inode != inode) or st.st_size < cp.offset:
                offset = 0
            else:
                offset = cp.offset

        with path.open("rb") as f:
            f.seek(offset)
            while True:
                line_start = f.tell()
                raw = f.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    # Partial line; do not advance checkpoint past it.
                    break
                try:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                except Exception:
                    line = raw.decode("latin-1", errors="replace").rstrip("\r\n")
                yield TailedLine(
                    line=line,
                    offset=line_start,
                    source_file=str(path),
                    inode=inode,
                )
                offset = f.tell()

        # Persist checkpoint at safe offset (end of last complete line consumed or same offset)
        st2 = path.stat() if path.exists() else st
        self.checkpoints.upsert(
            source_file=str(path),
            inode=inode,
            offset=offset,
            size=st2.st_size,
            mtime_ns=getattr(st2, "st_mtime_ns", int(st2.st_mtime * 1e9)),
            last_event_ts=cp.last_event_ts if cp else None,
            status="ok",
        )

    def mark_status(self, path: Path, status: str, last_event_ts: str | None = None) -> None:
        path = Path(path)
        cp = self.checkpoints.get(str(path))
        st = path.stat() if path.exists() else None
        self.checkpoints.upsert(
            source_file=str(path),
            inode=_file_inode(path) if path.exists() else (cp.inode if cp else None),
            offset=cp.offset if cp else 0,
            size=st.st_size if st else (cp.size if cp else 0),
            mtime_ns=getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9)) if st else (cp.mtime_ns if cp else 0),
            last_event_ts=last_event_ts or (cp.last_event_ts if cp else None),
            status=status,
        )
