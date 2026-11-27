# diag.py — run from project root
import joblib, pandas as pd

m = joblib.load("models/best_model.joblib")
b = joblib.load("models/preprocessor.joblib")

print("model type:", type(m).__name__)
print("n_features_in_:", getattr(m, "n_features_in_", None))
print("feature_names_in_:", getattr(m, "feature_names_in_", None))
print()

X = pd.read_csv("data/processed/transformed/X_train_transformed.csv", nrows=2)
print("transformed CSV shape:", X.shape)
print("CSV cols match output_order:", list(X.columns) == b["output_order"])