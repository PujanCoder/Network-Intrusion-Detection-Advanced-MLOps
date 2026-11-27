import pandas as pd
import joblib

from pathlib import Path
from sklearn.feature_selection import VarianceThreshold

ROOT_DIR = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT_DIR / "data" / "processed" / "transformed"


def remove_constant_features():

    X_train = pd.read_csv(DATA_DIR / "X_train_transformed.csv")
    X_test = pd.read_csv(DATA_DIR / "X_test_transformed.csv")

    print("Original training shape:", X_train.shape)

    # Fit selector using training data only
    selector = VarianceThreshold(threshold=0)

    X_train_selected = selector.fit_transform(X_train)
    X_test_selected = selector.transform(X_test)

    # Retrieve retained feature names
    selected_features = X_train.columns[selector.get_support()]

    X_train_selected = pd.DataFrame(
        X_train_selected,
        columns=selected_features
    )

    X_test_selected = pd.DataFrame(
        X_test_selected,
        columns=selected_features
    )

    # Identify removed features
    removed_features = X_train.columns[
        ~selector.get_support()
    ].tolist()

    print("\nREMOVED CONSTANT FEATURES")
    print("--------------------------------")

    for feature in removed_features:
        print(feature)

    print("\nTotal removed:", len(removed_features))

    # Save selected datasets
    X_train_selected.to_csv(
        DATA_DIR / "X_train_selected.csv",
        index=False
    )

    X_test_selected.to_csv(
        DATA_DIR / "X_test_selected.csv",
        index=False
    )

    joblib.dump(
        selector,
        DATA_DIR / "feature_selector.pkl"
    )

    # Record the selected schema inside the preprocessor bundle so serving can
    # select the model's input columns without re-fitting anything.
    bundle_path = ROOT_DIR / "models" / "preprocessor.joblib"

    if bundle_path.exists():
        bundle = joblib.load(bundle_path)
        bundle["model_features"] = list(selected_features)
        bundle["removed_features"] = removed_features
        joblib.dump(bundle, bundle_path)

    print("\nFINAL DATASET SHAPES")
    print("Training:", X_train_selected.shape)
    print("Testing:", X_test_selected.shape)


if __name__ == "__main__":
    remove_constant_features()