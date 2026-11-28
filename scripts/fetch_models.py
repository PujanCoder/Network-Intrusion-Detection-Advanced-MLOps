#!/usr/bin/env python3
"""Materialise the model artefacts the serving app needs before it starts.

Why this exists: ``models/*.joblib`` are DVC outputs and ``.gitignore`` keeps the
batch artefacts out of git, so a Render build (which only clones the repo) starts
with ``models/best_model.joblib`` and ``models/preprocessor.joblib`` missing. The
Zeek model is different: it is committed on purpose, so it is only checked here.

The script is deliberately non-fatal. A build that cannot reach DagsHub still has
to produce a running service: the app reports the missing model on
``/api/v1/health`` and keeps scoring Zeek events. Pass ``--strict`` in CI when a
missing artefact should fail the build instead.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DVC_DIR = ROOT / ".dvc"
TMP_PREFIX = ".fetch-"


@dataclass(frozen=True)
class Artifact:
    name: str
    relative_path: str
    required: bool
    tracked_by: str

    @property
    def path(self) -> Path:
        return ROOT / self.relative_path


ARTIFACTS: tuple[Artifact, ...] = (
    Artifact("cicids_model", "models/best_model.joblib", True, "dvc"),
    Artifact("cicids_preprocessor", "models/preprocessor.joblib", True, "dvc"),
    Artifact("zeek_model", "models/zeek/zeek_model.joblib", False, "git"),
)


@dataclass
class Report:
    artifacts: dict[str, dict[str, Any]] = field(default_factory=dict)
    attempts: list[dict[str, str]] = field(default_factory=list)
    secrets: set[str] = field(default_factory=set)

    def redact(self, text: str) -> str:
        for secret in self.secrets:
            if secret:
                text = text.replace(secret, "***")
        return text

    @property
    def missing_required(self) -> list[str]:
        return [
            name
            for name, state in self.artifacts.items()
            if state["required"] and not state["present"]
        ]

    def inspect(self) -> None:
        self.artifacts = {
            artifact.name: {
                "path": artifact.relative_path,
                "required": artifact.required,
                "tracked_by": artifact.tracked_by,
                "present": artifact.path.is_file() and artifact.path.stat().st_size > 0,
                "bytes": artifact.path.stat().st_size if artifact.path.is_file() else 0,
            }
            for artifact in ARTIFACTS
        }


def _register_secret(report: Report, value: str | None) -> None:
    if value:
        report.secrets.add(value)


def _dvc_command() -> list[str] | None:
    executable = shutil.which("dvc")
    if executable:
        return [executable]
    try:
        import dvc  # noqa: F401
    except ImportError:
        return None
    return [sys.executable, "-m", "dvc"]


def _dvc(*args: str, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    command = _dvc_command()
    if command is None:
        raise RuntimeError("dvc is not installed")
    return subprocess.run(
        [*command, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _dags_hub_username() -> str | None:
    """Owner from the configured remote URL, e.g. dagshub.com/<owner>/<repo>.s3."""

    explicit = os.getenv("DAGSHUB_USERNAME")
    if explicit:
        return explicit
    try:
        config = (DVC_DIR / "config").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in config.splitlines():
        if "endpointurl" not in line and "url" not in line:
            continue
        value = line.split("=", 1)[-1].strip()
        parsed = urllib.parse.urlparse(value)
        if parsed.netloc.endswith("dagshub.com"):
            parts = [part for part in parsed.path.split("/") if part]
            if parts:
                return parts[0]
    return None


def _set_local(*args: str) -> None:
    result = _dvc("remote", "modify", "origin", "--local", *args)
    if result.returncode != 0:
        raise RuntimeError(f"dvc remote modify failed: {result.stderr.strip()[:300]}")


def _clear_local_credentials() -> None:
    """Remove the credentials we injected so they do not outlive the build."""

    for option in ("auth", "user", "password"):
        try:
            _dvc("remote", "modify", "origin", "--local", "--unset", option)
        except Exception:  # noqa: BLE001 - best effort cleanup
            pass


def _credential_modes(report: Report) -> list[tuple[str, list[tuple[str, ...]]]]:
    """Credential strategies to try, in order. Values come from the environment."""

    modes: list[tuple[str, list[tuple[str, ...]]]] = []
    if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
        _register_secret(report, os.getenv("AWS_ACCESS_KEY_ID"))
        _register_secret(report, os.getenv("AWS_SECRET_ACCESS_KEY"))
        modes.append(("environment AWS keys", []))
    token = os.getenv("DAGSHUB_USER_TOKEN")
    if token:
        _register_secret(report, token)
        username = _dags_hub_username()
        if username:
            modes.append(
                (
                    "DagsHub basic auth",
                    [("auth", "basic"), ("user", username), ("password", token)],
                )
            )
    return modes


def pull_with_dvc(report: Report, targets: list[str], verbose: bool = False) -> bool:
    if not DVC_DIR.is_dir():
        report.attempts.append({"strategy": "dvc", "outcome": "skipped: no .dvc directory"})
        return False
    if _dvc_command() is None:
        report.attempts.append({"strategy": "dvc", "outcome": "skipped: dvc not installed"})
        return False

    modes = _credential_modes(report) or [("no credentials configured", [])]
    for name, settings in modes:
        try:
            _clear_local_credentials()
            for key, value in settings:
                _set_local(key, value)
            args = ["pull", *targets, "-r", "origin"]
            if verbose:
                args.append("-v")
            result = _dvc(*args)
            if result.returncode == 0:
                outcome = "ok"
            elif "do not exist neither locally nor on remote" in result.stderr:
                outcome = (
                    "failed: the remote does not have the objects dvc.lock points at "
                    "(the artefact was never pushed) - run `dvc push` or the "
                    "publish-artifacts workflow"
                )
            else:
                outcome = f"failed: {report.redact(result.stderr.strip())[:400]}"
            report.attempts.append({"strategy": f"dvc ({name})", "outcome": outcome})
            if result.returncode == 0:
                return True
        except Exception as exc:  # noqa: BLE001 - reported, never fatal
            report.attempts.append({"strategy": f"dvc ({name})", "outcome": f"error: {report.redact(str(exc))[:300]}"})
        finally:
            _clear_local_credentials()
    return False


def _safe_extract(archive: Path, destination: Path) -> None:
    destination = destination.resolve()

    def _check(name: str) -> None:
        target = (destination / name).resolve()
        if not str(target).startswith(str(destination) + os.sep) and target != destination:
            raise RuntimeError(f"archive entry escapes destination: {name}")

    if tarfile.is_tarfile(archive):
        with tarfile.open(archive) as handle:
            for member in handle.getmembers():
                _check(member.name)
                if member.issym() or member.islnk():
                    raise RuntimeError(f"archive contains links: {member.name}")
            handle.extractall(destination, filter="data")
        return
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as handle:
            for name in handle.namelist():
                _check(name)
            handle.extractall(destination)
        return
    raise RuntimeError(f"unsupported archive format: {archive.name}")


def download_artifacts(report: Report, url: str) -> bool:
    token = os.getenv("MODEL_ARTIFACTS_TOKEN")
    _register_secret(report, token)
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    suffix = ".zip" if url.split("?")[0].endswith(".zip") else ".tar.gz"
    try:
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=300) as response, tempfile.NamedTemporaryFile(
            suffix=suffix, prefix=TMP_PREFIX, delete=False
        ) as handle:
            shutil.copyfileobj(response, handle)
            archive = Path(handle.name)
        report.attempts.append({"strategy": "https archive", "outcome": f"downloaded {url.split('?')[0]}"})
        try:
            _safe_extract(archive, ROOT)
        finally:
            archive.unlink(missing_ok=True)
        return True
    except (urllib.error.URLError, RuntimeError, OSError) as exc:
        report.attempts.append(
            {"strategy": "https archive", "outcome": f"failed: {report.redact(str(exc))[:300]}"}
        )
        return False


def _print_summary(report: Report) -> None:
    print("artefact status")
    for state in report.artifacts.values():
        flag = "ok" if state["present"] else ("MISSING" if state["required"] else "absent (optional)")
        print(f"  {state['path']:<38} {flag:<18} {state['bytes']:>10} B  [{state['tracked_by']}]")


def _print_action_required(report: Report) -> None:
    missing = report.missing_required
    print()
    print("ACTION REQUIRED: the CICIDS baseline artefacts are not in this deployment.")
    print(f"  missing: {', '.join(missing)}")
    print("  The service still starts; /api/v1/health reports cicids_model.loaded = false,")
    print("  and POST /api/v1/ingest/cic answers 503. Zeek scoring is unaffected.")
    print()
    print("  Fix it with either:")
    print("    1. dvc pull  (DagsHub remote) with DAGSHUB_USER_TOKEN (+ DAGSHUB_USERNAME) set,")
    print("       or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the DagsHub repo settings.")
    print("    2. MODEL_ARTIFACTS_URL pointing at a tar.gz/zip that contains models/.")
    print()
    for attempt in report.attempts:
        print(f"  attempt [{attempt['strategy']}]: {attempt['outcome']}")


def run(check_only: bool = False, strict: bool = False, verbose: bool = False) -> int:
    report = Report()
    report.inspect()

    if not check_only:
        missing = [
            artifact.relative_path
            for artifact in ARTIFACTS
            if artifact.required and not (artifact.path.is_file() and artifact.path.stat().st_size > 0)
        ]
        if missing:
            fetched = pull_with_dvc(report, missing, verbose=verbose)
            if not fetched:
                url = os.getenv("MODEL_ARTIFACTS_URL")
                if url:
                    download_artifacts(report, url)
            report.inspect()

    _print_summary(report)
    if not check_only and report.attempts and not report.missing_required:
        for attempt in report.attempts:
            print(f"  attempt [{attempt['strategy']}]: {attempt['outcome']}")

    if report.missing_required:
        _print_action_required(report)
        return 1 if strict else 0

    if not check_only:
        print("all required artefacts present")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="report status without downloading")
    parser.add_argument("--strict", action="store_true", help="exit 1 when a required artefact is missing")
    parser.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    parser.add_argument("-v", "--verbose", action="store_true", help="pass -v to dvc")
    args = parser.parse_args(argv)

    if args.json:
        report = Report()
        report.inspect()
        print(json.dumps({"artifacts": report.artifacts, "missing": report.missing_required}, indent=2))
        return 1 if (args.strict and report.missing_required) else 0

    return run(check_only=args.check, strict=args.strict, verbose=args.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
