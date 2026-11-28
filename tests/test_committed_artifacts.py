"""Guard the CICIDS artefacts that ship in the repository.

The two artefacts are committed to Git, so the deployed service loads them
directly instead of waiting for a DVC pull. That makes the bytes part of the
repository contract: a truncated or swapped file has to fail here rather than in
a Render build. The fixtures are two real flows captured in CICIDS2017
(Friday-WorkingHours-Afternoon-DDos), one DDoS and one BENIGN.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.serving.predictor import DEFAULT_MODEL_PATH, DEFAULT_PREPROCESSOR_PATH, Predictor

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cicids"

pytestmark = pytest.mark.skipif(
    not (DEFAULT_MODEL_PATH.is_file() and DEFAULT_PREPROCESSOR_PATH.is_file()),
    reason="CICIDS artefacts are not present in this checkout",
)


@pytest.fixture(scope="module")
def predictor() -> Predictor:
    return Predictor(DEFAULT_MODEL_PATH, DEFAULT_PREPROCESSOR_PATH)


def test_committed_pair_states_its_contract(predictor):
    assert isinstance(predictor.model_features, list) and predictor.model_features
    assert len(predictor.feature_order) == 78
    assert len(predictor.model_features) == 68
    assert predictor.model.n_features_in_ == len(predictor.model_features)
    assert predictor.classes == ["BENIGN", "DDoS"]


@pytest.mark.parametrize(("fixture", "expected"), [("ddos_flow.json", "DDoS"), ("benign_flow.json", "BENIGN")])
def test_committed_pair_classifies_captured_flows(predictor, fixture, expected):
    flow = json.loads((FIXTURES / fixture).read_text())

    result = predictor.predict(flow)

    assert result["label"] == expected
    assert result["confidence"] >= 0.9
    assert result["is_attack"] is (expected == "DDoS")
