"""Structural checks for dvc.yaml and dvc.lock.

dvc.yaml once lost its top-level ``stages:`` key and gained a mis-indented
sibling, which PyYAML rejects ("Expected <block end>, but found '<block mapping
start>'") and which blocks every DVC command, including ``dvc push``. Nothing
caught it because the data pipeline is not exercised by the unit suite.

These tests are pure structure: no dvc binary, no dataset, no training.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DVC_YAML = ROOT / "dvc.yaml"
DVC_LOCK = ROOT / "dvc.lock"
ARTIFACTS = ("models/best_model.joblib", "models/preprocessor.joblib")
STAGE_KEYS = {"cmd", "deps", "params", "outs", "metrics", "plots", "foreach", "vars", "frozen", "desc"}


@pytest.fixture(scope="module")
def pipeline() -> dict:
    return yaml.safe_load(DVC_YAML.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def lock() -> dict:
    if not DVC_LOCK.is_file():
        pytest.skip("dvc.lock is not present in this checkout")
    return yaml.safe_load(DVC_LOCK.read_text(encoding="utf-8"))


def _paths(items) -> list[str]:
    return [item if isinstance(item, str) else next(iter(item)) for item in (items or [])]


def _lock_paths(items) -> list[str]:
    return [item["path"] for item in (items or [])]


def _param_names(items, lock_params) -> tuple[set[str], set[str]]:
    declared = set(_paths(items))
    recorded: set[str] = set()
    for values in (lock_params or {}).values():
        if isinstance(values, dict):
            recorded |= set(values)
    return declared, recorded


def test_dvc_yaml_parses_and_has_a_stages_mapping(pipeline):
    assert isinstance(pipeline, dict), "dvc.yaml must be a mapping"
    assert "stages" in pipeline, "dvc.yaml lost its top-level 'stages:' key"
    assert isinstance(pipeline["stages"], dict), "every stage must be nested under 'stages:'"
    assert pipeline["stages"], "dvc.yaml declares no stages"


def test_every_stage_has_a_command_and_only_stage_keys(pipeline):
    for name, stage in pipeline["stages"].items():
        assert isinstance(stage, dict), f"stage {name!r} is not a mapping"
        assert stage.get("cmd"), f"stage {name!r} has no cmd"
        unknown = set(stage) - STAGE_KEYS
        assert not unknown, f"stage {name!r} has unknown keys: {sorted(unknown)}"


def test_stages_never_share_an_output(pipeline):
    """DVC refuses overlapping outs, so a duplicate here breaks every command."""

    owners: dict[str, str] = {}
    for name, stage in pipeline["stages"].items():
        for path in _paths(stage.get("outs")) + _paths(stage.get("metrics")):
            assert path not in owners, f"{path} is an output of both {owners[path]!r} and {name!r}"
            owners[path] = name


def test_the_batch_artifacts_are_declared_outputs(pipeline):
    outs = {path: name for name, stage in pipeline["stages"].items() for path in _paths(stage.get("outs"))}
    for artifact in ARTIFACTS:
        assert artifact in outs, f"{artifact} is not an output of any stage"


def test_validation_stage_consumes_the_pipeline_artifacts(pipeline):
    stages = pipeline["stages"]
    validator = next(
        (name for name, stage in stages.items() if "validate_artifacts" in (stage.get("cmd") or "")),
        None,
    )
    assert validator, "the artefact validation stage disappeared"
    deps = set(_paths(stages[validator].get("deps")))
    for artifact in ARTIFACTS:
        assert artifact in deps, f"{validator} no longer depends on {artifact}"


def test_lock_matches_the_declared_stages(pipeline, lock):
    assert lock.get("schema"), "dvc.lock has no schema entry"
    declared = set(pipeline["stages"])
    recorded = set(lock.get("stages") or {})
    assert recorded == declared, (
        "dvc.lock and dvc.yaml disagree - "
        f"missing from lock: {sorted(declared - recorded)}, "
        f"stale in lock: {sorted(recorded - declared)}. "
        "Refresh with `dvc commit` (no retraining) or `dvc repro` after changing dvc.yaml."
    )


def test_lock_records_the_same_inputs_and_outputs(pipeline, lock):
    for name, stage in pipeline["stages"].items():
        recorded = lock["stages"][name]
        assert stage.get("cmd") == recorded.get("cmd"), f"{name}: cmd differs from dvc.lock"

        declared_deps = set(_paths(stage.get("deps")))
        recorded_deps = set(_lock_paths(recorded.get("deps")))
        assert declared_deps == recorded_deps, (
            f"{name}: deps differ from dvc.lock (yaml-only {sorted(declared_deps - recorded_deps)}, "
            f"lock-only {sorted(recorded_deps - declared_deps)})"
        )

        declared_params, recorded_params = _param_names(stage.get("params"), recorded.get("params"))
        assert declared_params == recorded_params, f"{name}: params differ from dvc.lock"

        declared_outs = set(_paths(stage.get("outs")) + _paths(stage.get("metrics")))
        recorded_outs = set(_lock_paths(recorded.get("outs")) + _lock_paths(recorded.get("metrics")))
        assert declared_outs == recorded_outs, (
            f"{name}: outputs differ from dvc.lock (yaml-only {sorted(declared_outs - recorded_outs)}, "
            f"lock-only {sorted(recorded_outs - declared_outs)})"
        )


def test_lock_pins_both_artifacts_with_a_hash(lock):
    outs = {
        entry["path"]: entry
        for stage in (lock.get("stages") or {}).values()
        for key in ("outs", "metrics")
        for entry in (stage.get(key) or [])
        if isinstance(entry, dict)
    }
    for artifact in ARTIFACTS:
        entry = outs.get(artifact)
        assert entry is not None, f"{artifact} is not recorded in dvc.lock"
        assert entry.get("md5"), f"{artifact} has no md5 in dvc.lock"
        assert entry.get("size"), f"{artifact} has no size in dvc.lock"


def test_dvc_records_use_relative_posix_paths(pipeline):
    """Windows checkouts must push the same paths Render pulls."""

    for name, stage in pipeline["stages"].items():
        for path in _paths(stage.get("deps")) + _paths(stage.get("outs")) + _paths(stage.get("metrics")):
            assert "\\" not in path, f"{name}: backslash in DVC path {path!r}"
            assert not path.startswith("/"), f"{name}: absolute DVC path {path!r}"
