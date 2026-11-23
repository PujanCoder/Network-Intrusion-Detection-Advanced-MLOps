
import pandas as pd
import numpy as np

from src.features.data_cleaning import clean_data, handle_outliers_iqr


def test_clean_data_removes_duplicates():
    df = pd.DataFrame({
        "Feature": [1, 2, 2, 3],
        "Label": ["BENIGN", "DDoS", "DDoS", "BENIGN"]
    })

    result = clean_data(df)

    assert len(result) == 3
    assert not result.duplicated().any()


def test_clean_data_removes_missing_labels():
    df = pd.DataFrame({
        "Feature": [1, 2, 3],
        "Label": ["BENIGN", None, "DDoS"]
    })

    result = clean_data(df)

    assert result["Label"].notna().all()


def test_clean_data_replaces_infinite_values():
    df = pd.DataFrame({
        "Feature": [1.0, np.inf, 3.0],
        "Label": ["BENIGN", "DDoS", "BENIGN"]
    })

    result = clean_data(df)

    assert np.isfinite(result["Feature"]).all()


def test_handle_outliers_iqr_returns_dataframe():
    df = pd.DataFrame({
        "Feature": [10, 11, 12, 13, 14, 1000]
    })

    result, report = handle_outliers_iqr(df)

    assert isinstance(result, pd.DataFrame)
    assert isinstance(report, pd.DataFrame)
    assert len(result) == len(df)
