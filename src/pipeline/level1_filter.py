# =============================================================================
# Уровень 1: быстрая фильтрация (SYN-спайки + Isolation Forest на агрегатах времени).
# =============================================================================
"""Level 1: fast statistical filtering (ТЗ) — SYN spikes + optional IF scores."""

from __future__ import annotations

import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.features.aggregate_traffic import aggregate_flows_by_time


def syn_spike_mask(
    series: pd.Series,
    multiplier: float = 3.0,
) -> pd.Series:
    """Flag timesteps where SYN count exceeds mean + multiplier * std."""
    m = series.astype(float)
    mu, sigma = m.mean(), m.std()
    if sigma == 0 or np.isnan(sigma):
        return pd.Series(False, index=m.index)
    return m > (mu + multiplier * sigma)


def level1_scores(
    X_agg: pd.DataFrame,
    if_model_path: str | Path | None,
    syn_col: str = "SYN_Flag_Count",
    syn_multiplier: float = 3.0,
) -> pd.DataFrame:
    """
    Combine rule-based SYN spike with optional IsolationForest on aggregated features.
    Returns columns: l1_syn_spike (bool), l1_if_anomaly (bool or False if no model).
    """
    out = pd.DataFrame(index=X_agg.index)
    if syn_col in X_agg.columns:
        out["l1_syn_spike"] = syn_spike_mask(X_agg[syn_col], multiplier=syn_multiplier)
    else:
        out["l1_syn_spike"] = False

    out["l1_if_anomaly"] = False
    if if_model_path and Path(if_model_path).is_file():
        try:
            model = joblib.load(if_model_path)
        except Exception as e:
            warnings.warn(
                "L1 IsolationForest: не удалось загрузить модель; "
                f"ветка IF на L1 отключена ({e.__class__.__name__}: {e}).",
                UserWarning,
                stacklevel=2,
            )
            model = None
        if model is None:
            out["l1_triggered"] = out["l1_syn_spike"] | out["l1_if_anomaly"]
            return out
        num = X_agg.select_dtypes(include=[np.number]).fillna(0)
        expected = getattr(model, "feature_names_in_", None)
        if expected is not None and not set(expected).issubset(num.columns):
            # IF обучен на признаках потоков; агрегаты по окнам — другая схема колонок.
            missing = set(expected) - set(num.columns)
            warnings.warn(
                "L1 IsolationForest: признаки модели не совпадают с колонками минутных агрегатов "
                f"(нет: {sorted(missing)[:8]}{'…' if len(missing) > 8 else ''}). "
                "Ветка IF на L1 отключена — используйте артефакт "
                "`if_model_agg.joblib`, обученный тем же пайплайном, что и L1 "
                "(`scripts/02_train_all.py`, `make_aggregate_numeric_frame`).",
                UserWarning,
                stacklevel=2,
            )
        elif expected is not None:
            pred = model.predict(num[list(expected)])
            out["l1_if_anomaly"] = pred == -1
        else:
            try:
                pred = model.predict(num)
                out["l1_if_anomaly"] = pred == -1
            except ValueError as e:
                warnings.warn(
                    "L1 IsolationForest: не удалось применить модель к агрегатам; "
                    f"ветка IF на L1 отключена ({e}).",
                    UserWarning,
                    stacklevel=2,
                )

    out["l1_triggered"] = out["l1_syn_spike"] | out["l1_if_anomaly"]
    return out


def _normalize_ts(s: pd.Series) -> pd.Series:
    return pd.to_datetime(s, errors="coerce", utc=True).dt.tz_localize(None)


def flow_level1_flags(
    flow_df: pd.DataFrame,
    timestamp_col: str,
    artifacts_dir: str | Path,
    freq: str = "1min",
    syn_col_flow: str = "SYN Flag Count",
    syn_multiplier: float = 3.0,
) -> pd.Series:
    """
    Per-row L1 flag via time buckets (ТЗ). Rows without valid timestamp default to True
    so they still reach L2 (no timestamp → cannot aggregate).
    """
    if timestamp_col not in flow_df.columns:
        return pd.Series(True, index=flow_df.index)

    ts = _normalize_ts(flow_df[timestamp_col])
    triggered = pd.Series(True, index=flow_df.index)

    valid = ts.notna()
    if not valid.any():
        return triggered

    work = flow_df.loc[valid].copy()
    work[timestamp_col] = ts.loc[valid]

    agg = aggregate_flows_by_time(
        work,
        timestamp_col,
        freq=freq,
        syn_col=syn_col_flow if syn_col_flow in work.columns else None,
    )
    if agg.empty:
        return triggered

    X_agg = agg.set_index(timestamp_col)
    # Приоритет: agg обучен только на минутных колонках → if_agg_model.joblib / if_model_agg.joblib.
    art = Path(artifacts_dir)
    chosen = None
    for cand in (art / "if_agg_model.joblib", art / "if_model_agg.joblib", art / "if_model.joblib"):
        if cand.is_file():
            chosen = cand
            break
    l1 = level1_scores(
        X_agg,
        if_model_path=chosen,
        syn_col="SYN_Flag_Count",
        syn_multiplier=syn_multiplier,
    )

    bucket_index = pd.DatetimeIndex(_normalize_ts(agg[timestamp_col]))
    trig_by_bucket = pd.Series(l1["l1_triggered"].to_numpy(), index=bucket_index)

    buckets = ts.dt.floor(freq)

    def _lookup(b):
        if pd.isna(b):
            return True
        key = pd.Timestamp(b)
        if key in trig_by_bucket.index:
            v = trig_by_bucket.loc[key]
            if isinstance(v, pd.Series):
                return bool(v.any())
            return bool(v)
        return False

    mapped = buckets.map(_lookup)
    triggered.loc[valid] = mapped.loc[valid].astype(bool)
    return triggered
