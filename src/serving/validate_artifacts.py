"""Validate that the persisted preprocessor and batch model agree.

This stage is read-only: it never rewrites the artefacts it inspects, so DVC
can treat ``models/preprocessor.joblib`` as a stable output of the pipeline.
"""

import json
from pathlib import Path

import joblib
import pandas as pd


def main() -> None:
    model = joblib.load("models/best_model.joblib")
    bundle = joblib.load("models/preprocessor.joblib")

    pre = bundle["preprocessor"]
    feat_in = bundle["feature_order"]
    model_features = bundle.get("model_features")

    sample = pd.DataFrame([{c: 0.0 for c in feat_in}])
    transformed = pre.transform(sample)
    out_cols = (
        list(transformed.columns)
        if hasattr(transformed, "columns")
        else list(bundle["output_order"])
    )

    model_feats = getattr(model, "feature_names_in_", None)
    if model_feats is not None:
        model_feats = list(model_feats)

    n_model = getattr(model, "n_features_in_", None)
    n_pre = len(out_cols)

    missing = [c for c in (model_feats or []) if c not in out_cols]
    schema_matches = model_features is not None and list(model_features) == list(
        model_feats or []
    )

    ok = (
        (n_model is None)
        or (
            model_feats is not None
            and not missing
            and schema_matches
            and len(model_features) == n_model
        )
    )

    out = {
        "ok": bool(ok),
        "n_model_features": n_model,
        "n_preprocessor_features": n_pre,
        "feature_order_len": len(feat_in),
        "model_features_recorded": model_features is not None,
        "model_features_match": schema_matches,
        "model_features_missing_from_preprocessor": missing,
    }

    Path("reports").mkdir(exist_ok=True)
    Path("reports/serving_validation.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))

    if not ok:
        raise SystemExit(f"validation failed: {out}")


if __name__ == "__main__":
    main()
