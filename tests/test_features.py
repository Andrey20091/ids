# =============================================================================
# Тесты: DNS-признаки и агрегация потоков по времени.
# =============================================================================
import pandas as pd

from src.features.aggregate_traffic import aggregate_flows_by_time
from src.features.dns_tunnel_features import dns_features_from_qname_series


def test_dns_entropy():
    """Энтропия и длина QNAME для двух разных строк."""
    s = pd.Series(["example.com", "aaaaaaaaaaaaaaaaaaaaaa"])
    f = dns_features_from_qname_series(s)
    assert "dns_qname_entropy" in f.columns
    assert f.iloc[0]["dns_qname_len"] == len("example.com")


def test_aggregate_requires_timestamp():
    """Агрегация по окну времени даёт хотя бы один бакет."""
    df = pd.DataFrame(
        {
            "ts": pd.date_range("2024-01-01", periods=5, freq="min"),
            "SYN Flag Count": [1, 2, 100, 1, 2],
            "Flow Packets/s": [1.0, 1.0, 1.0, 1.0, 1.0],
        }
    )
    agg = aggregate_flows_by_time(df, "ts", freq="5min", syn_col="SYN Flag Count")
    assert len(agg) >= 1
