from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class ParsedLine:
    ok: bool
    record: dict[str, Any] | None
    error: str | None = None


def parse_zeek_json_line(line: str) -> ParsedLine:
    raw = line.strip()
    if not raw:
        return ParsedLine(ok=False, record=None, error="empty line")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        return ParsedLine(ok=False, record=None, error=f"json decode error: {e.msg}")
    if not isinstance(obj, dict):
        return ParsedLine(ok=False, record=None, error="json line is not an object")
    return ParsedLine(ok=True, record=obj)
