# =============================================================================
# Числовые признаки, извлекаемые из полей заголовков потока (под embedding / RF).
# =============================================================================
"""Features derived from packet / flow headers for embedding-ready pipelines."""

from __future__ import annotations

import pandas as pd


def flow_header_fingerprint_numeric(df: pd.DataFrame, n_buckets: int = 512) -> pd.Series:
    """
    Числовой отпечаток ключевых полей потока (аналог «сырого заголовка» для табличного ML).

    Конкатенация строковых полей → ``hash % n_buckets``. Используется RF/LSTM/AE вместе с hdr_*.
    """
    parts: list[pd.Series] = []
    for col in (
        "Protocol",
        "Destination Port",
        "Source IP",
        "SYN Flag Count",
        "FIN Flag Count",
        "RST Flag Count",
    ):
        if col in df.columns:
            parts.append(df[col].astype(str))
    if not parts:
        return pd.Series(0.0, index=df.index, dtype=float)
    acc = parts[0]
    for p in parts[1:]:
        acc = acc + "|" + p
    return acc.map(lambda s: float(hash(s) % n_buckets))


def select_header_numeric_columns(df: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """
    Вернуть подмножество числовых колонок из списка имён, присутствующих в ``df``.

    Параметры
    ----------
    df : pd.DataFrame
        Таблица потоков.
    columns : list[str]
        Имена колонок CICIDS-стиля (с пробелами).

    Возвращает
    -----------
    pd.DataFrame
        Подмножество ``df`` только с существующими колонками.
    """
    use = [c for c in columns if c in df.columns]
    return df[use].copy()
