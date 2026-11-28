#!/usr/bin/env python3
"""Validate the CICIDS artefacts exactly the way the serving app loads them.

``src.serving.predictor.Predictor`` is the code that runs on Render, so this
script instantiates it instead of re-implementing the contract: a bundle that
cannot be loaded or cannot score a zero row is reported as unusable here, before
a deployment depends on it.

Reports size, md5, estimator, classes and feature counts, and flags drift against
the hashes recorded in ``dvc.lock`` (drift is not an error: ``dvc commit -f``
re-locks the file that is actually on disk).

Exit code is 0 unless ``--require`` is passed and the artefacts are unusable, so
it can run inside a build without taking the service down.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.serving.predictor import (  # noqa: E402
    DEFAULT_MODEL_PATH,
    DEFAULT_PREPROCESSOR_PATH,
    ArtifactError,
    Predictor,
    resolve_path,
)


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _lock_hashes(root: Path) -> dict[str, dict[str, Any]]:
    lock = root / "dvc.lock"
    if not lock.is_file():
        return {}
    payload = yaml.safe_load(lock.read_text(encoding="utf-8")) or {}
    recorded: dict[str, dict[str, Any]] = {}
    for stage in (payload.get("stages") or {}).values():
        for key in ("outs", "metrics", "deps"):
            for entry in stage.get(key) or []:
                if isinstance(entry, dict) and entry.get("path"):
                    recorded.setdefault(entry["path"], {"md5": entry.get("md5"), "size": entry.get("size")})
    return recorded


def check(model_path: Path, preprocessor_path: Path, root: Path = ROOT) -> dict[str, Any]:
    recorded = _lock_hashes(root)
    result: dict[str, Any] = {
        "ok": False,
        "error": None,
        "model": {"path": str(model_path), "exists": model_path.is_file()},
        "preprocessor": {"path": str(preprocessor_path), "exists": preprocessor_path.is_file()},
        "drift": {},
    }
    for label, path in (("model", model_path), ("preprocessor", preprocessor_path)):
        if not path.is_file():
            continue
        key = f"models/{path.name}"
        entry = result[label]
        entry["bytes"] = path.stat().st_size
        entry["md5"] = _md5(path)
        locked = recorded.get(key) or {}
        if locked:
            entry["lock_md5"] = locked.get("md5")
            entry["lock_size"] = locked.get("size")
            matches = locked.get("md5") == entry["md5"] and locked.get("size") == entry["bytes"]
            entry["matches_lock"] = matches
            if not matches:
                result["drift"][label] = {
                    "recorded": {"md5": locked.get("md5"), "size": locked.get("size")},
                    "actual": {"md5": entry["md5"], "size": entry["bytes"]},
                }

    try:
        predictor = Predictor(model_path, preprocessor_path)
    except ArtifactError as exc:
        result["error"] = f"{exc.kind}: {exc.detail}"
        return result
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    zeros = {column: 0.0 for column in predictor.feature_order}
    ones = {column: 1.0 for column in predictor.feature_order}
    try:
        predictions = {"zeros": predictor.predict(zeros), "ones": predictor.predict(ones)}
    except Exception as exc:  # noqa: BLE001
        result["error"] = f"smoke prediction failed: {type(exc).__name__}: {exc}"
        return result

    result.update(
        {
            "ok": True,
            "estimator": predictor.estimator,
            "classes": predictor.classes,
            "features": len(predictor.feature_order),
            "model_features": len(predictor.model_features) if predictor.model_features else None,
            "version": predictor.version,
            "smoke": predictions,
        }
    )
    return result


def _paths(args) -> tuple[Path, Path]:
    model = Path(args.model) if args.model else resolve_path("IDS_MODEL_PATH", DEFAULT_MODEL_PATH)
    preprocessor = (
        Path(args.preprocessor)
        if args.preprocessor
        else resolve_path("IDS_PREPROCESSOR_PATH", DEFAULT_PREPROCESSOR_PATH)
    )
    return model, preprocessor


def print_report(result: dict[str, Any]) -> None:
    for label in ("model", "preprocessor"):
        entry = result[label]
        if not entry.get("exists"):
            print(f"{label:<13} MISSING  {entry['path']}")
            continue
        lock_note = ""
        if "matches_lock" in entry:
            lock_note = " (matches dvc.lock)" if entry["matches_lock"] else " (differs from dvc.lock -> `dvc commit -f`)"
        print(f"{label:<13} {entry['bytes']:>10,} B  md5 {entry['md5']}  {entry['path']}{lock_note}")
    if result["ok"]:
        smoke = result["smoke"]
        print(
            f"loaded        estimator={result['estimator']} classes={result['classes']} "
            f"features={result['features']} version={result['version']}"
        )
        print(
            "smoke predict zeros -> "
            f"{smoke['zeros']['label']} ({smoke['zeros']['confidence']}) | "
            f"ones -> {smoke['ones']['label']} ({smoke['ones']['confidence']})"
        )
    else:
        print(f"UNUSABLE      {result['error']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model")
    parser.add_argument("--preprocessor")
    parser.add_argument("--require", action="store_true", help="exit 1 when the artefacts are unusable")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    model_path, preprocessor_path = _paths(args)
    result = check(model_path, preprocessor_path)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)
    if not result["ok"] and args.require:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
