# =============================================================================
# Корпоративные размеченные дампы / экспорт в таблицу (ТЗ: второй источник данных).
# =============================================================================
"""Load and validate corporate labeled flow CSV compatible with prepare."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd


# Минимум для согласования с prepare / flow_key (расширяется через feature_columns.yaml).
_REQUIRED_CORE = ("Label", "Source IP", "Destination IP")
_RECOMMENDED = ("Timestamp", "Protocol", "Destination Port")


def validate_corporate_labeled_csv(
    df: pd.DataFrame,
    *,
    strict_timestamp: bool = False,
) -> tuple[list[str], list[str]]:
    """
    Проверить табличный экспорт перед prepare.

    Возвращает ``(errors, warnings)``. При непустом ``errors`` файл не следует подавать в prepare без исправления.
    """
    errors: list[str] = []
    warnings: list[str] = []
    cols = set(df.columns.astype(str))

    for c in _REQUIRED_CORE:
        if c not in cols:
            errors.append(f"Отсутствует обязательная колонка «{c}».")

    if df.empty:
        errors.append("CSV не содержит строк.")

    ts = _RECOMMENDED[0]
    if ts not in cols:
        msg = f"Рекомендуется колонка «{ts}» для L1/LSTM по времени."
        if strict_timestamp:
            errors.append(msg)
        else:
            warnings.append(msg)

    for c in ("Protocol", "Destination Port"):
        if c not in cols:
            warnings.append(f"Нет колонки «{c}» — часть признаков и embedding будет недоступна.")

    return errors, warnings


def load_corporate_table(path: str | Path, **read_csv_kwargs: Any) -> pd.DataFrame:
    """
    Загрузить CSV корпоративного экспорта потоков.

    После загрузки выполните ``validate_corporate_labeled_csv`` или скрипт
    ``scripts/validate_corporate_csv.py``, затем ``main.py prepare --input ...``.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Corporate data file not found: {p}")
    return pd.read_csv(p, **read_csv_kwargs)
