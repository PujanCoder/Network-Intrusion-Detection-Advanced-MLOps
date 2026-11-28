#!/usr/bin/env python3
"""Keep the DVC remote configuration valid and authenticated.

DVC validates ``['remote "origin"']`` against the *type* implied by its URL. This
project's remote is an HTTPS DagsHub DVC endpoint, so the S3-only keys
``access_key_id``/``secret_access_key`` are rejected before any network call:

    ERROR: configuration error - config file error:
    extra keys not allowed @ data['remote']['origin']['access_key_id']

Every DVC command then fails, including ``dvc push``. This module removes keys
that do not belong to the configured remote type, applies credentials that are
supplied through the environment, and never prints a secret.

Usage::

    python scripts/dvc_remote.py --check     # report, exit 1 on invalid config
    python scripts/dvc_remote.py --fix       # strip invalid keys, use env token
    python scripts/dvc_remote.py --clear     # remove stored credentials
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
REMOTE = "origin"
SECTION = f"'remote \"{REMOTE}\"'"
SECTION_RE = re.compile(r"^\s*\[(?P<name>.+)\]\s*$")
KEY_RE = re.compile(r"^\s*(?P<key>[A-Za-z0-9_.\-]+)\s*=\s*(?P<value>.*)$")

S3_ONLY_KEYS = {
    "access_key_id",
    "secret_access_key",
    "session_token",
    "profile",
    "endpointurl",
    "region",
    "sse",
    "sse_kms_key_id",
    "acl",
    "grant_read",
    "requester_pays",
    "configpath",
    "connect_timeout",
    "read_timeout",
    "use_ssl",
}
HTTP_ONLY_KEYS = {"auth", "user", "password", "ask_password"}
CREDENTIAL_KEYS = ("auth", "user", "password")


@dataclass
class LocalConfig:
    """Line-preserving view of the remote section in ``.dvc/config.local``."""

    path: Path
    lines: list[str] = field(default_factory=list)
    section_index: int | None = None
    section_end: int | None = None

    @classmethod
    def load(cls, path: Path) -> "LocalConfig":
        config = cls(path)
        if path.is_file():
            config.lines = path.read_text(encoding="utf-8").splitlines()
        config._scan()
        return config

    def _scan(self) -> None:
        section_index = None
        for index, line in enumerate(self.lines):
            match = SECTION_RE.match(line)
            if not match:
                continue
            if section_index is None and match.group("name").strip() == SECTION:
                section_index = index
                continue
            if section_index is not None:
                self.section_index = section_index
                self.section_end = index
                return
        if section_index is not None:
            self.section_index = section_index
            self.section_end = len(self.lines)

    def entries(self) -> dict[str, str]:
        if self.section_index is None or self.section_end is None:
            return {}
        found: dict[str, str] = {}
        for line in self.lines[self.section_index + 1 : self.section_end]:
            match = KEY_RE.match(line)
            if match:
                found[match.group("key")] = match.group("value").strip()
        return found

    def remove(self, keys: Iterable[str]) -> list[str]:
        keys = {key for key in keys}
        if self.section_index is None or self.section_end is None:
            return []
        removed: list[str] = []
        kept: list[str] = []
        for line in self.lines[self.section_index + 1 : self.section_end]:
            match = KEY_RE.match(line)
            if match and match.group("key") in keys:
                removed.append(match.group("key"))
                continue
            kept.append(line)
        self.lines[self.section_index + 1 : self.section_end] = kept
        self.section_end = self.section_index + 1 + len(kept)
        return removed

    def set(self, updates: dict[str, str]) -> None:
        for key, value in updates.items():
            line = f"    {key} = {value}"
            if self.section_index is None:
                if self.lines and self.lines[-1].strip():
                    self.lines.append("")
                self.lines.append(f"[{SECTION}]")
                self.lines.append(line)
                self.section_index = len(self.lines) - 2
                self.section_end = len(self.lines)
                continue
            replaced = False
            for index in range(self.section_index + 1, self.section_end or len(self.lines)):
                match = KEY_RE.match(self.lines[index])
                if match and match.group("key") == key:
                    self.lines[index] = line
                    replaced = True
                    break
            if not replaced:
                insert_at = self.section_end if self.section_end is not None else len(self.lines)
                self.lines.insert(insert_at, line)
                self.section_end = insert_at + 1

    def save(self) -> None:
        if not self.lines:
            if self.path.exists():
                self.path.unlink()
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


def remote_url(root: Path = ROOT, remote: str = REMOTE) -> str | None:
    """The effective ``url`` for the remote, local override included.

    ``.dvc/config.local`` wins over ``.dvc/config``, exactly like DVC's own
    precedence, so a machine-specific override is honoured. Neither file's ``url``
    is ever rewritten by this module.
    """

    override = LocalConfig.load(root / ".dvc" / "config.local").entries().get("url")
    if override:
        return override
    config = root / ".dvc" / "config"
    if not config.is_file():
        return None
    wanted = f"'remote \"{remote}\"'"
    inside = False
    for line in config.read_text(encoding="utf-8").splitlines():
        match = SECTION_RE.match(line)
        if match:
            inside = match.group("name").strip() == wanted
            continue
        if inside:
            entry = KEY_RE.match(line)
            if entry and entry.group("key") == "url":
                return entry.group("value").strip()
    return None


def remote_kind(url: str | None) -> str:
    if not url:
        return "unknown"
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme in {"http", "https"}:
        return "http"
    if scheme in {"s3", "s3a"}:
        return "s3"
    if scheme in {"ssh", "sftp"}:
        return "ssh"
    if scheme in {"gdrive", "gs", "azure", "webdav", "webdavs", "hdfs"}:
        return scheme
    return "local"


def dagshub_owner(url: str | None) -> str | None:
    if not url:
        return None
    host = urllib.parse.urlparse(url).netloc.lower()
    if not host.endswith("dagshub.com"):
        return None
    parts = [part for part in urllib.parse.urlparse(url).path.split("/") if part]
    return parts[0] if parts else None


def env_token() -> str | None:
    return os.getenv("DAGSHUB_USER_TOKEN") or os.getenv("DAGSHUB_TOKEN")


def _env_username(url: str | None) -> str | None:
    return os.getenv("DAGSHUB_USERNAME") or dagshub_owner(url)


def sanitize(root: Path = ROOT) -> list[str]:
    """Remove keys that belong to a different remote type. Never touches the URL."""

    config = LocalConfig.load(root / ".dvc" / "config.local")
    entries = config.entries()
    kind = remote_kind(remote_url(root))
    invalid: set[str] = set()
    if kind == "http":
        invalid = S3_ONLY_KEYS & set(entries)
    elif kind == "s3":
        invalid = HTTP_ONLY_KEYS & set(entries)
    removed = config.remove(invalid)
    if removed:
        config.save()
    return sorted(removed)


def apply_env_credentials(root: Path = ROOT, overwrite: bool = False) -> tuple[list[str], bool]:
    """Store basic-auth credentials from the environment in ``.dvc/config.local``.

    Returns the key names written and whether a secret from the environment was
    stored. Values never leave this function.
    """

    token = env_token()
    if not token:
        return [], False
    config = LocalConfig.load(root / ".dvc" / "config.local")
    entries = config.entries()
    if entries.get("password") and not overwrite:
        if entries.get("auth") != "basic":
            config.set({"auth": "basic"})
            config.save()
            return ["auth"], False
        return [], False

    username = _env_username(remote_url(root))
    if not username:
        return [], False
    updates = {"auth": "basic", "user": username, "password": token}
    config.set(updates)
    config.save()
    try:
        os.chmod(config.path, 0o600)
    except OSError:
        pass
    return sorted(updates), True


def clear_credentials(root: Path = ROOT) -> list[str]:
    config = LocalConfig.load(root / ".dvc" / "config.local")
    removed = config.remove(CREDENTIAL_KEYS)
    if removed:
        config.save()
    return sorted(removed)


@dataclass
class Status:
    url: str | None
    kind: str
    keys: dict[str, str]
    problems: list[str]
    credential_source: str

    @property
    def ok(self) -> bool:
        return not self.problems

    def as_dict(self) -> dict[str, object]:
        return {
            "url": self.url,
            "kind": self.kind,
            "keys": sorted(self.keys),
            "problems": self.problems,
            "credentials": self.credential_source,
            "ok": self.ok,
        }


def status(root: Path = ROOT) -> Status:
    url = remote_url(root)
    kind = remote_kind(url)
    entries = LocalConfig.load(root / ".dvc" / "config.local").entries()

    problems: list[str] = []
    if url is None:
        problems.append("no url configured for remote 'origin' in .dvc/config")
    if kind == "http":
        invalid = sorted(S3_ONLY_KEYS & set(entries))
        if invalid:
            problems.append(
                "S3-only keys on an HTTP DVC remote: "
                + ", ".join(invalid)
                + " (fix: python scripts/dvc_remote.py --fix)"
            )
    elif kind == "s3":
        invalid = sorted(HTTP_ONLY_KEYS & set(entries))
        if invalid:
            problems.append("HTTP-only keys on an S3 remote: " + ", ".join(invalid))

    if entries.get("password"):
        source = "password stored in .dvc/config.local"
    elif env_token():
        source = "DAGSHUB_USER_TOKEN in the environment (not yet applied)"
    else:
        source = "none"
    return Status(url=url, kind=kind, keys=entries, problems=problems, credential_source=source)


def print_status(state: Status) -> None:
    print(f"remote origin: {state.url or '(unset)'}  [{state.kind}]")
    print(f"local keys: {', '.join(sorted(state.keys)) or '(none)'}")
    print(f"credentials: {state.credential_source}")
    for problem in state.problems:
        print(f"PROBLEM: {problem}")
    if state.ok:
        print("configuration valid")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--fix", action="store_true", help="strip invalid keys, apply env credentials")
    parser.add_argument("--check", action="store_true", help="report only (default)")
    parser.add_argument("--clear", action="store_true", help="remove stored credentials")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing stored password")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root)

    if args.clear:
        removed = clear_credentials(root)
        print("cleared: " + (", ".join(removed) or "nothing"))
    if args.fix:
        removed = sanitize(root)
        if removed:
            print("removed keys invalid for this remote type: " + ", ".join(removed))
        applied, _ = apply_env_credentials(root, overwrite=args.overwrite)
        if applied:
            print("applied credentials from environment: " + ", ".join(applied))

    state = status(root)
    if args.json:
        print(json.dumps(state.as_dict(), indent=2))
    else:
        print_status(state)
    return 0 if state.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
