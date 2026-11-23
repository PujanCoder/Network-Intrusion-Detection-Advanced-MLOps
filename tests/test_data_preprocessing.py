
import pandas as pd
from evidently import Report

from src.features.data_preprocessing import split_data


def test_split_data_shapes():
    df = pd.DataFrame({
        "Feature1": range(100),
        "Feature2": range(100, 200),
        "Label": ["BENIGN", "DDoS"] * 50
    })

    X_train, X_test, y_train, y_test = split_data(df)

    assert len(X_train) == 80
    assert len(X_test) == 20
    assert len(y_train) == 80
    assert len(y_test) == 20


def test_split_data_preserves_features():
    df = pd.DataFrame({
        "Feature1": range(100),
        "Feature2": range(100, 200),
        "Label": ["BENIGN", "DDoS"] * 50
    })

    X_train, X_test, y_train, y_test = split_data(df)

    assert "Label" not in X_train.columns
    assert "Label" not in X_test.columns
    assert list(X_train.columns) == list(X_test.columns)
