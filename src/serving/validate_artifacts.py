import json
from pathlib import Path

import joblib
import pandas as pd


def main() -> None:
    model = joblib.load("models/best_model.joblib")
    bundle = joblib.load("models/preprocessor.joblib")

    pre = bundle["preprocessor"]
    feat_in = bundle["feature_order"]

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

    ok = (n_model is None) or (model_feats is not None and not missing)

    if ok and model_feats is not None:
        bundle["model_features"] = model_feats
        joblib.dump(bundle, "models/preprocessor.joblib")

    out = {
        "ok": bool(ok),
        "n_model_features": n_model,
        "n_preprocessor_features": n_pre,
        "feature_order_len": len(feat_in),
        "model_features_missing_from_preprocessor": missing,
    }

    Path("reports").mkdir(exist_ok=True)
    Path("reports/serving_validation.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))

    if not ok:
        raise SystemExit(f"validation failed: {out}")


if __name__ == "__main__":
    main()