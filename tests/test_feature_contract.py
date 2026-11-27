import joblib
import pandas as pd

def test_feature_order_matches_preprocessor():
    bundle = joblib.load("models/preprocessor.joblib")
    pre, order = bundle["preprocessor"], bundle["feature_order"]

    # Build a zero-row DataFrame with exactly the stored columns
    sample = pd.DataFrame([{c: 0.0 for c in order}])

    # Will raise if column names or dtypes don't match what ColumnTransformer expects
    out = pre.transform(sample)
    assert out.shape[0] == 1

    model = joblib.load("models/best_model.joblib")
    if hasattr(model, "n_features_in_"):
        assert out.shape[1] == model.n_features_in_