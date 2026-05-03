# =============================================================================
# Загрузка таблиц CICIDS2017 (или совместимого CSV) — основной датасет кейса 4.
# =============================================================================
"""Load CICIDS2017 (or compatible) CSV tables."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def load_cicids_csv(path: str | Path, **read_csv_kwargs) -> pd.DataFrame:
    """
    Загрузить размеченный CSV потоков в стиле CICIDS2017.

    Параметры
    ----------
    path : str | Path
        Путь к файлу на диске.
    **read_csv_kwargs
        Дополнительные аргументы ``pandas.read_csv`` (разделитель, кодировка и т.д.).

    Возвращает
    -----------
    pd.DataFrame
        Таблица потоков с метками классов.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"CICIDS CSV not found: {p}")
    from src.ingest.cicids2017 import normalize_cicids2017_dataframe

    return normalize_cicids2017_dataframe(pd.read_csv(p, **read_csv_kwargs))
