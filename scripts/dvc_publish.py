#!/usr/bin/env python3
"""Publish the CICIDS artefacts to the configured DVC remote and prove they arrived.

One entry point for the whole upload, in the order that keeps DVC happy:

1. repair and authenticate the remote config (see ``scripts/dvc_remote.py``);
2. verify the artefacts load and score with the *serving* code;
3. verify every declared dependency is present (``dvc commit`` refuses otherwise);
4. ``dvc commit -f`` so ``dvc.lock`` describes the files that actually exist;
5. ``dvc push`` the two artefacts;
6. verify: ``dvc status -c`` plus an authenticated HEAD on each remote object.

Steps 4-5 touch caches, ``dvc.lock`` and the remote only. Model files are read,
never modified or deleted, and no pipeline stage is executed.

Exit codes: 0 ok, 2 credentials/config, 3 artefacts unusable, 4 push failed,
5 verification failed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import dvc_remote  # noqa: E402
import verify_artifacts  # noqa: E402
from src.serving.predictor import DEFAULT_MODEL_PATH, DEFAULT_PREPROCESSOR_PATH, resolve_path  # noqa: E402

TARGETS = ("models/best_model.joblib", "models/preprocessor.joblib")


def _dvc(*args: str, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
    command = [shutil.which("dvc") or sys.executable]
    if command[0] == sys.executable:
        command.append("-m")
        command.append("dvc")
    return subprocess.run(
        [*command, *args], cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False
    )


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remote_object_url(md5: str) -> str | None:
    url = dvc_remote.remote_url(ROOT)
    if dvc_remote.remote_kind(url) != "http":
        return None
    return f"{url.rstrip('/')}/files/md5/{md5[:2]}/{md5[2:]}"


def verify_remote_object(md5: str, expected_size: int | None = None) -> tuple[bool, str]:
    """HEAD the object on the HTTP remote. Returns (present, detail)."""

    url = remote_object_url(md5)
    if url is None:
        return True, "non-HTTP remote: verified with `dvc status -c` only"
    token = dvc_remote.env_token()
    username = os.getenv("DAGSHUB_USERNAME") or dvc_remote.dagshub_owner(dvc_remote.remote_url(ROOT))
    request = urllib.request.Request(url, method="HEAD")
    if token and username:
        credentials = base64.b64encode(f"{username}:{token}".encode()).decode()
        request.add_header("Authorization", f"Basic {credentials}")
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            length = response.headers.get("Content-Length")
            if response.status not in (200, 206):
                return False, f"HTTP {response.status}"
            if expected_size is not None and length is not None and int(length) != expected_size:
                return False, f"HTTP {response.status} but {length} B != {expected_size} B"
            return True, f"HTTP {response.status}, {length or '?'} B"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return False, f"network error: {exc.reason}"


def _cache_dir() -> Path:
    result = _dvc("cache", "dir")
    if result.returncode == 0 and result.stdout.strip():
        return Path(result.stdout.strip().splitlines()[-1])
    return ROOT / ".dvc" / "cache"


def _cache_root() -> Path:
    """Cache object root for this repo's layout (``files/md5`` since DVC 2)."""

    cache = _cache_dir()
    if (cache / "files").is_dir() or not any(cache.glob("??/*")):
        return cache / "files" / "md5"
    return cache


def _store_in_cache(path: Path, md5: str) -> Path:
    """Put the file in the content-addressed cache, like ``dvc commit`` does."""

    target = _cache_root() / md5[:2] / md5[2:]
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        try:
            os.chmod(target, 0o444)
        except OSError:
            pass
    return target


def relock(paths: tuple[Path, ...]) -> dict[str, dict[str, object]]:
    """Point ``dvc.lock`` at the files on disk without running the stage.

    ``dvc commit -f`` saves the whole ``ml_pipeline`` stage, so it refuses when a
    sibling output (``data/processed/*``, ``reports/*``) is absent - common on a
    machine that trained once and later cleaned intermediates. This rewrites only
    the md5/size of the given paths, then verifies nothing else moved.

    A ``path:`` line inside a ``params:`` block looks similar, so an entry is only
    recognised when its key indentation is exactly two spaces past a ``- `` marker.
    """

    lock_path = ROOT / "dvc.lock"
    before = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
    lines = lock_path.read_text(encoding="utf-8").splitlines()
    wanted = {f"models/{path.name}": path for path in paths}
    hashes = {name: _md5(path) for name, path in wanted.items()}
    sizes = {name: path.stat().st_size for name, path in wanted.items()}

    path_line = re.compile(r"^(?P<indent>\s*)(?:-\s*)?path:\s*(?P<path>.+?)\s*$")
    dash_line = re.compile(r"^(?P<indent>\s*)-\s")
    field_line = re.compile(r"^(?P<indent>\s*)(?P<key>md5|size):\s*(?P<value>.+?)\s*$")

    def entry_bounds(index: int) -> tuple[int, int] | None:
        match = path_line.match(lines[index])
        assert match is not None
        leading = len(match.group("indent"))
        # "- path: x" keeps the key two columns past the marker; "  path: x" does not
        key_indent = leading + (2 if lines[index][leading:].lstrip().startswith("-") else 0)
        start = None
        for cursor in range(index, max(index - 8, -1), -1):
            dash = dash_line.match(lines[cursor])
            if dash and len(dash.group("indent")) + 2 == key_indent:
                start = cursor
                break
        if start is None:
            return None
        end = start + 1
        while end < len(lines) and not dash_line.match(lines[end]):
            end += 1
        return start, end

    touched: list[str] = []
    for index, line in enumerate(lines):
        match = path_line.match(line)
        if not match or match.group("path") not in wanted:
            continue
        bounds = entry_bounds(index)
        if bounds is None:
            continue
        name = match.group("path")
        start, end = bounds
        for cursor in range(start, end):
            field = field_line.match(lines[cursor])
            if not field:
                continue
            value = hashes[name] if field.group("key") == "md5" else str(sizes[name])
            lines[cursor] = f"{field.group('indent')}{field.group('key')}: {value}"
        touched.append(name)

    if set(touched) != set(wanted):
        raise RuntimeError(f"could not relock every artefact, only found {sorted(set(touched))}")

    text = "\n".join(lines) + "\n"
    after = yaml.safe_load(text)

    def digests(payload):
        found = {}
        for stage_name, stage in (payload.get("stages") or {}).items():
            for key in ("outs", "metrics", "deps"):
                for item in stage.get(key) or []:
                    if isinstance(item, dict) and item.get("path"):
                        found[f"{stage_name}/{key}/{item['path']}"] = (item.get("md5"), item.get("size"))
        return found

    original, rewritten = digests(before), digests(after)
    changed = {key for key in set(original) | set(rewritten) if original.get(key) != rewritten.get(key)}
    allowed = {key for key in changed if key.split("/", 2)[2] in wanted}
    unexpected = changed - allowed
    if unexpected:
        raise RuntimeError(f"relock touched unexpected entries: {sorted(unexpected)}")

    lock_path.write_text(text, encoding="utf-8")
    for name, path in wanted.items():
        _store_in_cache(path, hashes[name])
        if path.stat().st_size != sizes[name]:
            raise RuntimeError(f"{name} changed size while publishing")
    return {name: {"md5": hashes[name], "size": sizes[name]} for name in wanted}


def publish(
    dry_run: bool = False,
    commit: bool = True,
    require_verification: bool = True,
) -> dict[str, object]:
    report: dict[str, object] = {"steps": [], "ok": False, "exit_code": 1}

    def step(name: str, outcome: str, detail: str = "") -> None:
        report["steps"].append({"step": name, "outcome": outcome, "detail": detail})  # type: ignore[index]

    removed = dvc_remote.sanitize(ROOT)
    if removed:
        step("config", "fixed", "removed keys invalid for this remote: " + ", ".join(removed))
    else:
        step("config", "ok", "no invalid remote keys")

    applied, _ = dvc_remote.apply_env_credentials(ROOT)
    state = dvc_remote.status(ROOT)
    if not state.ok:
        step("config", "failed", "; ".join(state.problems))
        report["exit_code"] = 2
        return report
    if state.kind in {"http", "ssh"} and not dvc_remote.env_token() and "password" not in state.keys:
        step(
            "credentials",
            "missing",
            "set DAGSHUB_USER_TOKEN (DagsHub token with repository write access) in the environment",
        )
        report["exit_code"] = 2
        return report
    step("credentials", "ok", state.credential_source + (("; applied " + ", ".join(applied)) if applied else ""))

    model_path = resolve_path("IDS_MODEL_PATH", DEFAULT_MODEL_PATH)
    preprocessor_path = resolve_path("IDS_PREPROCESSOR_PATH", DEFAULT_PREPROCESSOR_PATH)
    artifacts = verify_artifacts.check(model_path, preprocessor_path)
    if not artifacts["ok"]:
        step("artifacts", "unusable", str(artifacts["error"]))
        report["exit_code"] = 3
        return report
    drift = artifacts["drift"]
    step(
        "artifacts",
        "ok",
        f"{model_path.stat().st_size:,} B model, {preprocessor_path.stat().st_size:,} B preprocessor"
        + (f"; re-locking drift: {', '.join(sorted(drift))}" if drift else "; hashes match dvc.lock"),
    )

    check = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_dvc_deps.py"), "--json"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    blocking = []
    if check.returncode != 0 and check.stdout:
        try:
            blocking = json.loads(check.stdout).get("errors", [])
        except json.JSONDecodeError:
            blocking = [{"path": "unknown", "detail": check.stdout[-200:]}]
    if blocking:
        step("dependencies", "failed", "; ".join(f"{item.get('path')}: {item.get('state')}" for item in blocking))
        report["exit_code"] = 3
        return report
    step("dependencies", "ok", "every declared dependency is on disk")

    if dry_run:
        step("commit", "skipped", "--dry-run")
        step("push", "skipped", "--dry-run")
        report.update({"ok": True, "exit_code": 0})
        return report

    if commit:
        result = _dvc("commit", "-f")
        if result.returncode == 0:
            step("commit", "ok", "dvc.lock now describes the local artefacts")
        elif "does not exist" in (result.stderr + result.stdout):
            try:
                locked = relock((model_path, preprocessor_path))
            except Exception as exc:  # noqa: BLE001 - reported, never fatal
                step("commit", "failed", f"dvc commit refused and relock failed: {exc}")
                report["exit_code"] = 4
                return report
            step(
                "commit",
                "relocked",
                "dvc commit needs every sibling output of the stage; re-locked only "
                + ", ".join(f"{name} ({meta['md5']}, {meta['size']:,} B)" for name, meta in locked.items()),
            )
        else:
            step("commit", "failed", (result.stderr or result.stdout).strip()[:500])
            report["exit_code"] = 4
            return report

    result = _dvc("push", *TARGETS, "-r", "origin")
    if result.returncode != 0:
        step("push", "failed", (result.stderr or result.stdout).strip()[:500])
        report["exit_code"] = 4
        return report
    step("push", "ok", (result.stderr or result.stdout).strip()[:200] or "pushed")

    cloud = _dvc("status", "-c", *TARGETS)
    output = cloud.stderr + cloud.stdout
    offenders = [
        line.strip()
        for line in output.splitlines()
        if any(target in line for target in TARGETS)
        and any(word in line for word in ("missing", "not in cache", "new:", "deleted"))
    ]
    in_sync = cloud.returncode == 0 and not offenders
    step("remote status", "ok" if in_sync else "failed", (offenders and "; ".join(offenders)[:300]) or "targets in sync")

    objects = {}
    for path in (model_path, preprocessor_path):
        present, detail = verify_remote_object(_md5(path), path.stat().st_size)
        objects[str(path)] = {"present": present, "detail": detail}
    step(
        "remote objects",
        "ok" if all(item["present"] for item in objects.values()) else "failed",
        "; ".join(f"{Path(k).name}: {v['detail']}" for k, v in objects.items()),
    )
    report["objects"] = objects

    ok = in_sync and all(item["present"] for item in objects.values())
    if not ok and require_verification:
        report["exit_code"] = 5
        return report
    report.update({"ok": True, "exit_code": 0})
    return report


def lock_needs_commit() -> bool | None:
    """True when dvc.lock differs from HEAD - the deploy reads the committed lock.

    A re-lock rewrites hashes locally; unless the file is pushed, Render resolves
    the *previous* objects and downloads artefacts that are not what was published.
    """

    if not (ROOT / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain", "--", "dvc.lock"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return bool(result.stdout.strip())


def print_report(report: dict[str, object]) -> None:
    for item in report["steps"]:  # type: ignore[index]
        detail = f" - {item['detail']}" if item.get("detail") else ""
        print(f"[{item['outcome']:<9}] {item['step']}{detail}")
    print("RESULT: " + ("published and verified" if report["ok"] else f"stopped (exit {report['exit_code']})"))
    if report["ok"] and lock_needs_commit():
        print("NEXT: dvc.lock changed - commit and push it, or the next build pulls the previous hashes.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="check everything, change nothing")
    parser.add_argument("--no-commit", action="store_true", help="push the locked hashes as-is")
    parser.add_argument("--no-verify", action="store_true", help="do not fail when the HEAD check fails")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = publish(dry_run=args.dry_run, commit=not args.no_commit, require_verification=not args.no_verify)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report)
    return int(report["exit_code"])  # type: ignore[arg-type]


if __name__ == "__main__":
    raise SystemExit(main())
