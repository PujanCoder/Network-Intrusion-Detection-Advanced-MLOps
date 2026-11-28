#!/usr/bin/env python3
"""Verify that every path dvc.yaml declares actually exists before dvc commit/push.

``dvc commit -f`` and ``dvc push`` both refuse to run when any declared
dependency is missing on disk. The failure is reported one path at a time
(``dependency 'src\\models\\tracking.py' does not exist``), which hides the real
cause: a stale or partially checked-out working tree.

This check separates the three cases so the message tells you what to do:

* ``missing_source``   - a tracked code/param file is absent: your checkout is
                         incomplete (``git status``, ``git pull``);
* ``missing_output``   - the path is produced by an earlier stage: run the
                         pipeline, or it is simply not there yet;
* ``missing_dvc_input``- the path is DVC-tracked data: ``dvc pull`` it.

Exit code is 1 only for ``missing_source`` (and for unknown declared params).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Finding:
    stage: str
    path: str
    state: str
    detail: str = ""
    action: str = ""

    @property
    def is_error(self) -> bool:
        return self.state in {"missing_source", "unknown_param"}


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    checked: int = 0

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.is_error]

    def as_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "errors": [f.__dict__ for f in self.errors],
            "findings": [f.__dict__ for f in self.findings],
        }


def _paths(items) -> list[str]:
    return [item if isinstance(item, str) else next(iter(item)) for item in (items or [])]


def dvc_tracked_outputs(root: Path) -> set[str]:
    """Output paths declared by any ``*.dvc`` file in the repository."""

    tracked: set[str] = set()
    for dvc_file in root.rglob("*.dvc"):
        if not dvc_file.is_file():
            continue  # the .dvc/ directory itself matches the glob
        try:
            payload = yaml.safe_load(dvc_file.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        for entry in payload.get("outs") or []:
            if isinstance(entry, dict) and entry.get("path"):
                # paths inside a .dvc file are relative to that file's directory
                target = dvc_file.parent / entry["path"]
                try:
                    tracked.add(target.relative_to(root).as_posix())
                except ValueError:
                    tracked.add(target.as_posix())
    return tracked


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _param_exists(params_file: str, dotted: str, root: Path) -> bool:
    target = root / params_file
    if not target.is_file():
        return False
    data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
    node: Any = data
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def audit(root: Path = ROOT) -> Report:
    pipeline = yaml.safe_load((root / "dvc.yaml").read_text(encoding="utf-8")) or {}
    stages = pipeline.get("stages") or {}
    lock_path = root / "dvc.lock"
    lock = (yaml.safe_load(lock_path.read_text(encoding="utf-8")) or {}) if lock_path.is_file() else {}
    lock_stages = lock.get("stages") or {}

    produced: dict[str, str] = {}
    recorded_md5: dict[str, str] = {}
    for stage_name, stage in list(stages.items()) + list(lock_stages.items()):
        for key in ("outs", "metrics"):
            for entry in stage.get(key) or []:
                if isinstance(entry, str):
                    produced.setdefault(entry, stage_name)
                elif isinstance(entry, dict) and entry.get("path"):
                    produced.setdefault(entry["path"], stage_name)
                    if entry.get("md5"):
                        recorded_md5[entry["path"]] = entry["md5"]
    for stage in lock_stages.values():
        for entry in stage.get("deps") or []:
            if isinstance(entry, dict) and entry.get("path") and entry.get("md5"):
                recorded_md5.setdefault(entry["path"], entry["md5"])

    tracked = dvc_tracked_outputs(root)
    report = Report()

    for stage_name, stage in stages.items():
        for dep in _paths(stage.get("deps")):
            report.checked += 1
            target = root / dep
            if target.exists():
                detail = ""
                if target.is_file() and dep in recorded_md5:
                    actual = _md5(target)
                    detail = "md5 matches dvc.lock" if actual == recorded_md5[dep] else (
                        f"md5 {actual} != dvc.lock {recorded_md5[dep]} (will be re-locked by `dvc commit -f`)"
                    )
                report.findings.append(Finding(stage_name, dep, "present", detail))
                continue
            if dep in produced:
                report.findings.append(
                    Finding(stage_name, dep, "missing_output", f"built by stage {produced[dep]!r}",
                            f"run `dvc repro {produced[dep]}` or `dvc pull {dep}`")
                )
            elif any(dep == t or dep.startswith(t + "/") for t in tracked):
                report.findings.append(
                    Finding(stage_name, dep, "missing_dvc_input", "DVC-tracked data",
                            "run `dvc pull` for this path")
                )
            else:
                report.findings.append(
                    Finding(stage_name, dep, "missing_source", "not produced by any stage and not DVC-tracked",
                            "restore it from git: `git status`, then `git checkout -- <path>` or `git pull`")
                )

        params = stage.get("params") or []
        params_files = []
        for entry in params:
            if isinstance(entry, dict):
                for source, keys in entry.items():
                    params_files.append((source, keys))
        if not params_files:
            # plain names resolve in params.yaml
            params_files = [("params.yaml", _paths(params))]
        for source, keys in params_files:
            for key in keys if isinstance(keys, list) else [keys]:
                report.checked += 1
                if key in produced:  # stage-level param reference, not a value
                    continue
                if _param_exists(source, str(key), root):
                    report.findings.append(Finding(stage_name, f"{source}:{key}", "present"))
                else:
                    report.findings.append(
                        Finding(stage_name, f"{source}:{key}", "unknown_param",
                                f"declared in dvc.yaml but absent from {source}",
                                "fix dvc.yaml or params.yaml")
                    )
    return report


def print_report(report: Report) -> None:
    for finding in report.findings:
        if finding.state == "present" and not finding.detail:
            continue
        marker = "ERROR" if finding.is_error else "note "
        print(f"[{marker}] {finding.stage:<22} {finding.path}"
              + (f"\n        {finding.state}: {finding.detail}" if finding.detail else ""))
        if finding.action:
            print(f"        -> {finding.action}")
    if report.errors:
        print(f"\n{len(report.errors)} blocking problem(s); dvc commit/push will fail until they are fixed.")
    else:
        print(f"OK: {report.checked} declared inputs checked, nothing missing.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    parser.add_argument("--root", default=str(ROOT), help="repository root (default: this checkout)")
    args = parser.parse_args(argv)

    report = audit(Path(args.root))
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print_report(report)
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
