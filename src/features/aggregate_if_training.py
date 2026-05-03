# =============================================================================
# Построение агрегатов по времени для обучения IF на уровне L1 (кейс 4).
# =============================================================================
"""Утилиты для обучения Isolation Forest на минутных агрегатах (согласованность с L1)."""

from __future__ import annotations

import numpy as np
import pandas as pd
import warnings

from src.features.aggregate_traffic import aggregate_flows_by_time


def make_aggregate_numeric_frame(
    df: pd.DataFrame,
    timestamp_col: str,
    freq: str = "1min",
) -> pd.DataFrame | None:
    """
    Преобразовать потоки в минутные бакеты и вернуть только числовые колонки.

    Используется для обучения ``if_model_agg.joblib`` с теми же именами колонок,
    что и при инференсе L1 (после resample в aggregate_flows_by_time).

    Параметры
    ----------
    df : pd.DataFrame
        Потоки с колонкой времени и SYN/скоростями.
    timestamp_col : str
        Имя столбца времени.
    freq : str
        Частота ресемплинга (как в settings aggregation.resample_freq).

    Возвращает
    -----------
    pd.DataFrame | None
        Числовая матрица агрегатов или None, если данных недостаточно.
    """
    if timestamp_col not in df.columns:
        return None
    work = df.copy()
    work[timestamp_col] = pd.to_datetime(work[timestamp_col], errors="coerce", utc=True).dt.tz_localize(None)
    work = work.dropna(subset=[timestamp_col])
    if work.empty:
        return None

    syn_col = "SYN Flag Count" if "SYN Flag Count" in work.columns else None
    agg = aggregate_flows_by_time(
        work,
        timestamp_col,
        freq=freq,
        syn_col=syn_col,
    )
    if agg.empty or len(agg) < 3:
        return None

    ts_name = agg.columns[0]
    num = agg.drop(columns=[ts_name], errors="ignore").select_dtypes(include=[np.number]).fillna(0.0)
    if num.empty:
        return None
    return num


def make_aggregate_numeric_with_timestamps(
    df: pd.DataFrame,
    timestamp_col: str,
    freq: str = "1min",
) -> tuple[pd.Series, pd.DataFrame] | None:
    """
    Как ``make_aggregate_numeric_frame``, но возвращает ещё ряд меток времени бакетов
    (для сопоставления с агрегатом меток is_attack на валидации agg-IF).
    """
    if timestamp_col not in df.columns:
        return None
    work = df.copy()
    work[timestamp_col] = pd.to_datetime(work[timestamp_col], errors="coerce", utc=True).dt.tz_localize(None)
    work = work.dropna(subset=[timestamp_col])
    if work.empty:
        return None
    syn_col = "SYN Flag Count" if "SYN Flag Count" in work.columns else None
    agg = aggregate_flows_by_time(
        work,
        timestamp_col,
        freq=freq,
        syn_col=syn_col,
    )
    if agg.empty or len(agg) < 2:
        return None
    ts_name = agg.columns[0]
    ts = pd.to_datetime(agg[ts_name])
    num = agg.drop(columns=[ts_name], errors="ignore").select_dtypes(include=[np.number]).fillna(0.0)
    if num.empty:
        return None
    return ts.reset_index(drop=True), num.reset_index(drop=True)


def aggregate_bucket_attack_labels(
    df: pd.DataFrame,
    timestamp_col: str,
    attack_col: str,
    freq: str,
) -> pd.Series:
    """
    Индекс — floor(timestamp, freq); значение — max(is_attack) по потокам в окне.
    """
    work = df[[timestamp_col, attack_col]].copy()
    work[timestamp_col] = pd.to_datetime(work[timestamp_col], errors="coerce", utc=True).dt.tz_localize(None)
    work = work.dropna(subset=[timestamp_col])
    return work.groupby(pd.Grouper(key=timestamp_col, freq=freq))[attack_col].max()


def agg_if_alignment_f1(
    bucket_ts: pd.Series,
    agg_num: pd.DataFrame,
    model,
    bucket_attack: pd.Series,
) -> dict[str, float]:
    """
    Proxy F1: предсказание IF ``-1`` как «подозрительное окно» vs наличие атаки в бакете.

    Честная proxy-метрика без отдельной разметки аномалий: синхронизация только по времени и is_attack.
    """
    from sklearn.metrics import f1_score

    num = agg_num.select_dtypes(include=[np.number]).fillna(0.0)
    expected = getattr(model, "feature_names_in_", None)
    cols = list(expected) if expected is not None else list(num.columns)
    cols = [c for c in cols if c in num.columns]
    if not cols:
        return {"f1": 0.0, "n_used": 0}
    try:
        pred = model.predict(num[cols])
        pred_binary = (pred == -1).astype(int)
        floors = pd.DatetimeIndex(pd.to_datetime(bucket_ts).dt.floor("min"))
        ba = bucket_attack.copy()
        ba.index = pd.DatetimeIndex(ba.index).floor("min")
        ba = ba.groupby(level=0).max()
        y = ba.reindex(floors).fillna(0).astype(int).clip(0, 1).values
        p = pred_binary.astype(int)
        n = len(y)
        if n == 0:
            return {"f1": 0.0, "n_used": 0.0}
        f1 = float(f1_score(y, p, zero_division=0))
        return {"f1": f1, "n_used": float(n)}
    except Exception as e:
        warnings.warn(
            f"agg_if_alignment_f1 fallback to zero metrics due to error: {e}",
            UserWarning,
            stacklevel=2,
        )
        return {"f1": 0.0, "n_used": 0.0, "error": str(e)}
