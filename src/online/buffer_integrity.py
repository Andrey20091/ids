# =============================================================================
# Лёгкая целостность буфера для watermark (первая строка данных, без полного хеша файла).
# =============================================================================
from __future__ import annotations

import hashlib
import zlib

import pandas as pd


def fingerprint_data_row(row: pd.Series) -> str:
    """Стабильный SHA-256 по значениям строки (порядок колонок как в row.index)."""
    parts = [str(row[c]) for c in row.index]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def fingerprint_first_data_row(df: pd.DataFrame) -> str | None:
    if df is None or len(df) == 0:
        return None
    return fingerprint_data_row(df.iloc[0])


def fingerprint_prefix_last_row(df: pd.DataFrame, rows_processed: int) -> str | None:
    """Отпечаток последней строки уже обработанного префикса (индекс rows_processed - 1)."""
    if rows_processed <= 0 or df is None or len(df) == 0:
        return None
    idx = int(rows_processed) - 1
    if idx < 0 or idx >= len(df):
        return None
    return fingerprint_data_row(df.iloc[idx])


def _interior_sample_indices(rows_processed: int) -> list[int]:
    """Индексы строк строго внутри префикса (не 0 и не rows_processed-1)."""
    k = int(rows_processed)
    if k < 3:
        return []
    raw = {1, k // 2, max(1, k - 2)}
    return sorted(i for i in raw if 0 < i < k - 1)


def prefix_interior_checksum(df: pd.DataFrame, rows_processed: int) -> str | None:
    """
    CRC32 по SHA-отпечаткам выборочных строк внутри префикса — ловит правки между «головой» и границей.
    """
    k = int(rows_processed)
    if k < 3 or df is None or len(df) < k:
        return None
    idxs = _interior_sample_indices(k)
    if not idxs:
        return None
    parts = [fingerprint_data_row(df.iloc[i]).encode("utf-8") for i in idxs]
    blob = b"|".join(parts)
    return format(zlib.crc32(blob) & 0xFFFFFFFF, "08x")
