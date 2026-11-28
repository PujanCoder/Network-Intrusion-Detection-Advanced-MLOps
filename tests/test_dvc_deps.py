"""Tests for scripts/check_dvc_deps.py.

``dvc commit -f`` stops at the first declared dependency that is absent
(``dependency 'src\\models\\tracking.py' does not exist``). The checker exists to
say *why* a path is missing - stale checkout, not-yet-built output, or data that
needs ``dvc pull`` - so the fix is obvious instead of a guessing game.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_dvc_deps.py"
REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location("check_dvc_deps", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["check_dvc_deps"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def checker():
    return load_module()


@pytest.fixture
def tree(tmp_path):
    """A miniature repository with one stage."""

    (tmp_path / "src" / "models").mkdir(parents=True)
    (tmp_path / "src" / "models" / "train_model.py").write_text("print('train')\n", encoding="utf-8")
    (tmp_path / "params.yaml").write_text(
        yaml.safe_dump({"model": {"path": "models/best_model.joblib"}}), encoding="utf-8"
    )
    (tmp_path / "dvc.yaml").write_text(
        yaml.safe_dump(
            {
                "stages": {
                    "ml_pipeline": {
                        "cmd": "python -m src.models.train_model",
                        "deps": ["src/models/train_model.py"],
                        "params": ["model"],
                        "outs": ["models/best_model.joblib"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "dvc.lock").write_text(
        yaml.safe_dump(
            {
                "schema": "2.0",
                "stages": {
                    "ml_pipeline": {
                        "cmd": "python -m src.models.train_model",
                        "deps": [{"path": "src/models/train_model.py", "md5": "x", "size": 14}],
                        "outs": [{"path": "models/best_model.joblib", "md5": "y", "size": 1}],
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def states(report) -> dict[str, str]:
    return {finding.path: finding.state for finding in report.findings}


def test_repository_has_no_missing_source_dependencies(checker):
    report = checker.audit(REPO_ROOT)

    assert report.checked > 0
    assert report.errors == [], [f"{f.path}: {f.state} {f.detail}" for f in report.errors]


def test_declared_sources_exist_and_match_the_lock(checker):
    report = checker.audit(REPO_ROOT)
    present = {f.path: f.detail for f in report.findings if f.state == "present" and f.detail}

    assert "src/models/tracking.py" in present
    assert present["src/models/tracking.py"] == "md5 matches dvc.lock"
    assert all("dvc.lock" in detail for detail in present.values())


def test_missing_source_is_a_blocking_error(checker, tree, tmp_path):
    (tmp_path / "src" / "models" / "train_model.py").unlink()

    report = checker.audit(tmp_path)

    assert states(report)["src/models/train_model.py"] == "missing_source"
    assert [f.path for f in report.errors] == ["src/models/train_model.py"]
    assert checker.main(["--root", str(tmp_path)]) == 1


def test_output_of_another_stage_is_a_note_not_an_error(checker, tree, tmp_path):
    pipeline = yaml.safe_load((tmp_path / "dvc.yaml").read_text(encoding="utf-8"))
    pipeline["stages"]["validate"] = {
        "cmd": "python -m src.serving.validate_artifacts",
        "deps": ["models/best_model.joblib"],
    }
    (tmp_path / "dvc.yaml").write_text(yaml.safe_dump(pipeline), encoding="utf-8")

    report = checker.audit(tmp_path)

    assert states(report)["models/best_model.joblib"] == "missing_output"
    assert report.errors == []


def test_dvc_tracked_input_is_a_note_and_paths_are_file_relative(checker, tree, tmp_path):
    """data/raw/dataset.dvc declares ``dataset`` relative to its own directory."""

    (tmp_path / "data" / "raw" / "dataset").mkdir(parents=True)
    (tmp_path / "data" / "raw" / "dataset.dvc").write_text(
        yaml.safe_dump({"outs": [{"path": "dataset", "md5": "z.dir", "nfiles": 2}]}), encoding="utf-8"
    )
    pipeline = yaml.safe_load((tmp_path / "dvc.yaml").read_text(encoding="utf-8"))
    pipeline["stages"]["ml_pipeline"]["deps"].append("data/raw/dataset/part-000.csv")
    (tmp_path / "dvc.yaml").write_text(yaml.safe_dump(pipeline), encoding="utf-8")

    report = checker.audit(tmp_path)

    assert states(report)["data/raw/dataset/part-000.csv"] == "missing_dvc_input"
    assert report.errors == []


def test_unknown_param_is_a_blocking_error(checker, tree, tmp_path):
    pipeline = yaml.safe_load((tmp_path / "dvc.yaml").read_text(encoding="utf-8"))
    pipeline["stages"]["ml_pipeline"]["params"] = ["model.missing_key"]
    (tmp_path / "dvc.yaml").write_text(yaml.safe_dump(pipeline), encoding="utf-8")

    report = checker.audit(tmp_path)

    assert states(report)["params.yaml:model.missing_key"] == "unknown_param"
    assert len(report.errors) == 1


def test_cli_reports_ok_on_a_healthy_tree(checker, tree, capsys):
    assert checker.main(["--root", str(tree)]) == 0
    assert "nothing missing" in capsys.readouterr().out


def test_cli_json_output(checker, tree, capsys):
    assert checker.main(["--root", str(tree), "--json"]) == 0
    payload = capsys.readouterr().out
    assert '"checked"' in payload
    assert '"errors": []' in payload
