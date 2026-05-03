import pandas as pd

from src.ingest.load_corporate import validate_corporate_labeled_csv


def test_validate_corporate_minimal_ok():
    df = pd.DataFrame(
        {
            "Label": ["BENIGN", "Attack"],
            "Source IP": ["10.0.0.1", "10.0.0.2"],
            "Destination IP": ["8.8.8.8", "1.1.1.1"],
            "Timestamp": ["2024-01-01", "2024-01-02"],
            "Protocol": [6, 6],
            "Destination Port": [80, 443],
        }
    )
    err, warn = validate_corporate_labeled_csv(df)
    assert not err
    assert not warn


def test_validate_corporate_missing_label_errors():
    df = pd.DataFrame({"Source IP": ["a"], "Destination IP": ["b"]})
    err, _ = validate_corporate_labeled_csv(df)
    assert err and any("Label" in e for e in err)


def test_validate_corporate_strict_timestamp():
    df = pd.DataFrame(
        {
            "Label": ["BENIGN"],
            "Source IP": ["10.0.0.1"],
            "Destination IP": ["8.8.8.8"],
        }
    )
    err, warn = validate_corporate_labeled_csv(df, strict_timestamp=False)
    assert not err
    assert any("Timestamp" in w for w in warn)
    err2, _ = validate_corporate_labeled_csv(df, strict_timestamp=True)
    assert err2
