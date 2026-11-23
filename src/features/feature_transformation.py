
import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from sklearn.preprocessing import PowerTransformer, StandardScaler
from sklearn.compose import ColumnTransformer


ROOT_DIR = Path(__file__).resolve().parents[2]

OUTPUT_DIR = (
    ROOT_DIR
    / "data"
    / "processed"
    / "transformed"
)


def transform_features(X_train, X_test, y_train, y_test):

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    X_train = X_train.copy()
    X_test = X_test.copy()

    # Identify binary features using training data
    binary_features = [
        col for col in X_train.columns
        if X_train[col].nunique() <= 2
    ]

    # Identify continuous numerical features
    continuous_features = [
        col
        for col in X_train.select_dtypes(include=np.number).columns
        if col not in binary_features
    ]

    # Calculate skewness using training data only
    skewness = X_train[continuous_features].skew()

    skewed_features = skewness[
        skewness.abs() > 1
    ].index.tolist()

    normal_features = [
        col for col in continuous_features
        if col not in skewed_features
    ]

    print("\nFEATURE TRANSFORMATION REPORT")
    print("-" * 40)
    print("Total features:", X_train.shape[1])
    print("Binary features:", len(binary_features))
    print("Highly skewed features:", len(skewed_features))
    print("Other continuous features:", len(normal_features))

    transformers = []

    if skewed_features:
        transformers.append(
            (
                "power",
                PowerTransformer(method="yeo-johnson"),
                skewed_features
            )
        )

    if normal_features:
        transformers.append(
            (
                "scaler",
                StandardScaler(),
                normal_features
            )
        )

    preprocessor = ColumnTransformer(
        transformers=transformers,
        remainder="passthrough",
        verbose_feature_names_out=False
    )

    preprocessor.set_output(transform="pandas")

    # Fit only on training data
    X_train_transformed = preprocessor.fit_transform(X_train)

    # Transform test data using training parameters
    X_test_transformed = preprocessor.transform(X_test)

    # Save transformed features
    X_train_transformed.to_csv(
        OUTPUT_DIR / "X_train_transformed.csv",
        index=False
    )

    X_test_transformed.to_csv(
        OUTPUT_DIR / "X_test_transformed.csv",
        index=False
    )

    # Save labels
    y_train.to_csv(
        OUTPUT_DIR / "y_train.csv",
        index=False
    )

    y_test.to_csv(
        OUTPUT_DIR / "y_test.csv",
        index=False
    )

    # Save fitted preprocessing pipeline
    joblib.dump(
        preprocessor,
        OUTPUT_DIR / "preprocessor.pkl"
    )

    print("\nTRANSFORMATION COMPLETED")
    print("-" * 40)
    print("Training shape:", X_train_transformed.shape)
    print("Testing shape:", X_test_transformed.shape)
    print("Preprocessor saved:", OUTPUT_DIR / "preprocessor.pkl")

    return X_train_transformed, X_test_transformed
