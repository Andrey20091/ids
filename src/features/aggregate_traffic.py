# =============================================================================
# Агрегация потоков по временным окнам для L1 (объём, SYN, частота).
# =============================================================================
"""Aggregated traffic metrics for fast L1 filtering (ТЗ: volume, frequency, ports)."""

from __future__ import annotations

import pandas as pd


def aggregate_flows_by_time(
    df: pd.DataFrame,
    timestamp_col: str,
    freq: str = "1min",
    syn_col: str | None = "SYN Flag Count",
) -> pd.DataFrame:
    """
    Ресемплинг строк потоков в бакеты времени (например 1 минута).

    Имена колонок после агрегации: пробелы заменены на ``_`` (``SYN_Flag_Count``).
    """
    d = df.copy()
    d[timestamp_col] = pd.to_datetime(d[timestamp_col], errors="coerce", utc=True).dt.tz_localize(None)
    d = d.dropna(subset=[timestamp_col])
    d = d.set_index(timestamp_col)
    agg: dict[str, str] = {}
    if "Flow Packets/s" in d.columns:
        agg["Flow Packets/s"] = "sum"
    else:
        d["_flow_count"] = 1.0
        agg["_flow_count"] = "sum"
    if syn_col and syn_col in d.columns:
        agg[syn_col] = "sum"
    out = d.resample(freq).agg(agg)
    out.columns = [c.replace(" ", "_") for c in out.columns]
    return out.reset_index()
