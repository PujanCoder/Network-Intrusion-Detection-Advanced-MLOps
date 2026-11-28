"""Tests for scripts/verify_artifacts.py (the pre-deploy artefact check)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
import pytest
import yaml
from sklearn.ensemble import RandomForestClassifier

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_artifacts.py"
COLUMNS = ["f1", "f2", "f3"]


class Passthrough:
    def __init__(self, columns: list[str]) -> None:
        self.columns = list(columns)

    def transform(self, frame: pd.DataFrame) -> pd.DataFrame:
        return frame[self.columns]


def load_module():
    spec = importlib.util.spec_from_file_location("verify_artifacts", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules["verify_artifacts"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def verifier():
    return load_module()


@pytest.fixture
def pair(tmp_path):
    columns = COLUMNS
    rows, labels = [], []
    for index in range(12):
        attack = index % 2 == 0
        rows.append({column: (index + 1) * (2 if attack else 0.5) for column in columns})
        labels.append("DDoS" if attack else "BENIGN")
    frame = pd.DataFrame(rows)
    model = RandomForestClassifier(n_estimators=5, random_state=0).fit(frame, labels)

    model_path = tmp_path / "best_model.joblib"
    preprocessor_path = tmp_path / "preprocessor.joblib"
    joblib.dump(model, model_path)
    joblib.dump(
        {
            "preprocessor": Passthrough(columns),
            "feature_order": columns,
            "model_features": columns,
            "model_version": "unit-test",
        },
        preprocessor_path,
    )
    return model_path, preprocessor_path


def test_a_compatible_pair_loads_and_scores(verifier, pair, tmp_path):
    result = verifier.check(pair[0], pair[1], root=tmp_path)

    assert result["ok"] is True
    assert result["classes"] == ["BENIGN", "DDoS"]
    assert result["features"] == len(COLUMNS)
    assert result["smoke"]["zeros"]["label"] in {"BENIGN", "DDoS"}
    assert 0.0 <= result["smoke"]["zeros"]["confidence"] <= 1.0
    assert result["model"]["bytes"] == pair[0].stat().st_size
    assert len(result["model"]["md5"]) == 32


def test_missing_files_are_unusable_and_only_fatal_with_require(verifier, tmp_path, capsys):
    missing_model = tmp_path / "nope.joblib"
    missing_pre = tmp_path / "nope2.joblib"

    result = verifier.check(missing_model, missing_pre, root=tmp_path)
    assert result["ok"] is False
    assert "missing" in result["error"]

    assert verifier.main(["--model", str(missing_model), "--preprocessor", str(missing_pre)]) == 0
    capsys.readouterr()
    assert (
        verifier.main(["--model", str(missing_model), "--preprocessor", str(missing_pre), "--require"]) == 1
    )


def test_corrupt_model_is_reported_not_raised(verifier, pair, tmp_path):
    pair[0].write_bytes(b"not a joblib file")

    result = verifier.check(pair[0], pair[1], root=tmp_path)

    assert result["ok"] is False
    assert "invalid" in result["error"] or "Error" in result["error"]


def test_preprocessor_without_feature_order_is_rejected(verifier, pair, tmp_path):
    joblib.dump({"preprocessor": Passthrough(COLUMNS)}, pair[1])

    result = verifier.check(pair[0], pair[1], root=tmp_path)

    assert result["ok"] is False
    assert "feature_order" in result["error"]


def test_schema_mismatch_between_model_and_preprocessor_is_rejected(verifier, pair, tmp_path):
    extra = COLUMNS + ["f_extra"]
    joblib.dump(
        {
            "preprocessor": Passthrough(extra),
            "feature_order": extra,
            "model_features": extra,
            "model_version": "unit-test",
        },
        pair[1],
    )

    result = verifier.check(pair[0], pair[1], root=tmp_path)

    assert result["ok"] is False
    assert "contract mismatch" in result["error"]


def test_drift_against_dvc_lock_is_reported(verifier, pair, tmp_path):
    (tmp_path / "dvc.lock").write_text(
        yaml.safe_dump(
            {
                "schema": "2.0",
                "stages": {
                    "ml_pipeline": {
                        "cmd": "x",
                        "outs": [
                            {"path": "models/best_model.joblib", "md5": "0" * 32, "size": 1},
                            {"path": "models/preprocessor.joblib", "md5": "1" * 32, "size": 1},
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.check(pair[0], pair[1], root=tmp_path)

    assert result["ok"] is True
    assert set(result["drift"]) == {"model", "preprocessor"}
    assert result["model"]["matches_lock"] is False


def test_matching_lock_is_reported_as_such(verifier, pair, tmp_path):
    import hashlib

    digests = {path.name: hashlib.md5(path.read_bytes()).hexdigest() for path in pair}
    (tmp_path / "dvc.lock").write_text(
        yaml.safe_dump(
            {
                "schema": "2.0",
                "stages": {
                    "ml_pipeline": {
                        "cmd": "x",
                        "outs": [
                            {
                                "path": f"models/{name}",
                                "md5": digest,
                                "size": (tmp_path / name).stat().st_size,
                            }
                            for name, digest in digests.items()
                        ],
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    result = verifier.check(pair[0], pair[1], root=tmp_path)

    assert result["ok"] is True
    assert result["drift"] == {}
    assert result["model"]["matches_lock"] is True


def test_json_output_is_machine_readable(verifier, pair, tmp_path, capsys):
    assert verifier.main(["--model", str(pair[0]), "--preprocessor", str(pair[1]), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["smoke"]["ones"]["confidence"] >= 0.0
