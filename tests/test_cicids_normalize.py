import warnings

import pandas as pd

from src.ingest.cicids2017 import ensure_flow_schema_for_ml, normalize_cicids2017_dataframe


def test_normalize_strips_bom_and_label_alias():
    df = pd.DataFrame({"\ufeffFlow Duration": [1.0], "label": ["BENIGN"]})
    out = normalize_cicids2017_dataframe(df)
    assert "Flow Duration" in out.columns
    assert "Label" in out.columns


def test_normalize_parses_trafficlabelling_timestamp_dayfirst():
    df = pd.DataFrame({"Timestamp": ["03/07/2017 08:55:58"], "Label": ["BENIGN"]})
    out = normalize_cicids2017_dataframe(df)
    assert pd.api.types.is_datetime64_any_dtype(out["Timestamp"])
    assert out["Timestamp"].notna().all()


def test_normalize_iso_proxy_timestamp_no_userwarning():
    """YYYY-MM-DD из proxy/ISO без dayfirst=True — без предупреждения pandas про dayfirst."""
    df = pd.DataFrame({"Timestamp": ["2023-11-15 01:13:21"], "Label": ["BENIGN"]})
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        out = normalize_cicids2017_dataframe(df)
    assert pd.api.types.is_datetime64_any_dtype(out["Timestamp"])
    assert str(out["Timestamp"].iloc[0]).startswith("2023-11-15")


def test_ensure_schema_adds_missing_base_columns():
    feat = {
        "label_column": "Label",
        "timestamp_column": "Timestamp",
        "numeric_features": ["Flow Duration", "hdr_ip_ttl_mean"],
        "categorical_for_embedding": {"protocol_column": "Protocol", "port_column": "Destination Port"},
        "context_columns": ["Source IP"],
    }
    raw = pd.DataFrame({"Flow Duration": [10.0]})
    out = ensure_flow_schema_for_ml(raw, feat)
    assert "Label" in out.columns
    assert "Timestamp" in out.columns
    assert "Protocol" in out.columns
    assert out["Destination Port"].iloc[0] == 0
    assert "Source IP" in out.columns
    # hdr_* не заполняются ensure (их даёт enrich)
    assert "hdr_ip_ttl_mean" not in out.columns
