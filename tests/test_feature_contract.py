"""Contract test between the persisted preprocessor and the batch model.

Both artefacts are outputs of the DVC ``ml_pipeline`` stage and are not
committed to git. When they are absent (clean checkout without ``dvc pull``)
the test is skipped, unless ``NDR_REQUIRE_ARTIFACTS=1`` is set, which turns a
missing artefact into a hard failure (CI uses this once artefacts are pulled).
"""

from __future__ import annotations

import os
from pathlib import Path

import joblib
import pandas as pd
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "models" / "best_model.joblib"
PREPROCESSOR_PATH = PROJECT_ROOT / "models" / "preprocessor.joblib"

MISSING = [str(path.relative_to(PROJECT_ROOT)) for path in (MODEL_PATH, PREPROCESSOR_PATH) if not path.exists()]
REQUIRE = os.getenv("NDR_REQUIRE_ARTIFACTS") == "1"

if MISSING and REQUIRE:
    pytest.fail(
        "NDR_REQUIRE_ARTIFACTS=1 but batch artefacts are missing: "
        f"{', '.join(MISSING)} (run `dvc pull` or `dvc repro`)",
        pytrace=False,
    )

pytestmark = pytest.mark.skipif(
    bool(MISSING),
    reason=f"batch artefacts not present ({', '.join(MISSING)}); run `dvc pull` or `dvc repro`",
)


def test_feature_order_matches_preprocessor():
    bundle = joblib.load(PREPROCESSOR_PATH)
    pre, order = bundle["preprocessor"], bundle["feature_order"]

    sample = pd.DataFrame([{column: 0.0 for column in order}])
    out = pre.transform(sample)
    assert out.shape[0] == 1

    model = joblib.load(MODEL_PATH)
    if hasattr(model, "n_features_in_"):
        assert out.shape[1] >= model.n_features_in_


def test_recorded_model_features_match_trained_model():
    bundle = joblib.load(PREPROCESSOR_PATH)
    model = joblib.load(MODEL_PATH)

    recorded = bundle.get("model_features")
    assert recorded, "preprocessor bundle is missing the recorded model feature schema"

    trained = getattr(model, "feature_names_in_", None)
    if trained is not None:
        assert list(recorded) == list(trained)
    assert len(recorded) == model.n_features_in_
