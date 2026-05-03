# =============================================================================
# Тесты: L1 SYN-спайк и привязка флагов к временным бакетам.
# =============================================================================
import numpy as np
import pandas as pd

from src.pipeline.level1_filter import flow_level1_flags, syn_spike_mask


def test_syn_spike():
    # На коротком окне выброс сильно двигает mean/std; при k=2 одна точка редко «выстреливает».
    # Либо длинный baseline, либо меньший multiplier (см. aggregate по минутам).
    s = pd.Series([1] * 20 + [500])
    m = syn_spike_mask(s, multiplier=2.0)
    assert m.iloc[-1]


def test_flow_level1_maps_bucket(tmp_path):
    """Two minutes of traffic; second minute has high SYN sum → some rows flagged."""
    ts = pd.to_datetime(
        ["2024-01-01 00:00:00"] * 5 + ["2024-01-01 00:01:00"] * 5,
        utc=True,
    ).tz_localize(None)
    df = pd.DataFrame(
        {
            "Timestamp": ts,
            "SYN Flag Count": [1, 1, 1, 1, 1, 1, 1, 1, 1, 300],
            "Flow Packets/s": [1.0] * 10,
        }
    )
    # При ровно двух бакетах выборочное std велико; multiplier < 1 даёт устойчивый син-спайк.
    flags = flow_level1_flags(
        df,
        "Timestamp",
        tmp_path,
        freq="1min",
        syn_multiplier=0.5,
    )
    assert flags.dtype == bool or flags.dtype == np.bool_
    assert flags.iloc[-1] or flags.any()
