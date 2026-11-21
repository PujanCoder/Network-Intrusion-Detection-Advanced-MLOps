import pandas as pd
import numpy as np
import joblib

from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import PowerTransformer, StandardScaler
from sklearn.compose import ColumnTransformer


ROOT_DIR = Path(__file__).resolve().parents[2]

DATA_PATH = ROOT_DIR / "data" / "processed" / "cleaned_dataset.csv"

OUTPUT_DIR = ROOT_DIR / "data" / "processed" / "transformed"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def transform_features(df):

    # Separate features and target
    X = df.drop(columns=["Label"])
    y = df["Label"]

    # Train-test split
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    # Identify binary features
    binary_features = [
        col for col in X_train.columns
        if X_train[col].nunique() <= 2
    ]

    # Identify continuous numerical features
    continuous_features = [
        col for col in X_train.select_dtypes(include=np.number).columns
        if col not in binary_features
    ]

    # Calculate skewness using training data only
    skewness = X_train[continuous_features].skew()

    # Highly skewed features
    skewed_features = skewness[
        skewness.abs() > 1
    ].index.tolist()

    # Remaining continuous features
    normal_features = [
        col for col in continuous_features
        if col not in skewed_features
    ]

    print("\nFEATURE TRANSFORMATION REPORT")
    print("--------------------------------")
    print("Total features:", X_train.shape[1])
    print("Binary features:", len(binary_features))
    print("Highly skewed features:", len(skewed_features))
    print("Other continuous features:", len(normal_features))

    # Define transformations
    transformers = []

    if skewed_features:
        transformers.append(
            ("power", PowerTransformer(method="yeo-johnson"), skewed_features)
        )

    if normal_features:
        transformers.append(
            ("scaler", StandardScaler(), normal_features)
        )

    # Binary features remain unchanged
    preprocessor = ColumnTransformer(
        transformers=transformers,
        remainder="passthrough",
        verbose_feature_names_out=False
    )

    # Preserve DataFrame output
    preprocessor.set_output(transform="pandas")

    # Fit only on training data
    X_train_transformed = preprocessor.fit_transform(X_train)

    # Apply the learned transformations to test data
    X_test_transformed = preprocessor.transform(X_test)

    # Save transformed datasets
    X_train_transformed.to_csv(
        OUTPUT_DIR / "X_train_transformed.csv",
        index=False
    )

    X_test_transformed.to_csv(
        OUTPUT_DIR / "X_test_transformed.csv",
        index=False
    )

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
    print("--------------------------------")
    print("Training shape:", X_train_transformed.shape)
    print("Testing shape:", X_test_transformed.shape)
    print("Saved transformation pipeline.")
    print("Output directory:", OUTPUT_DIR)

    return preprocessor


if __name__ == "__main__":

    df = pd.read_csv(DATA_PATH)

    print("Original dataset:", df.shape)

    transform_features(df)