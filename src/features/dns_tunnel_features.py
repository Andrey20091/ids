# =============================================================================
# Признаки DNS-туннелирования: длина и энтропия QNAME (кейс 4, L2).
# =============================================================================
"""DNS tunneling heuristics (ТЗ level 2) — for DNS query logs or derived columns."""

from __future__ import annotations

import math
import string

import pandas as pd


def _entropy(s: str) -> float:
    """Нормализованная энтропия Шеннона по символам строки (0 для пустой)."""
    if not s:
        return 0.0
    prob = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in prob.values() if p > 0)


def _label_stats(name: str) -> tuple[int, int, float]:
    """Число меток, макс. длина метки, доля цифр во всём имени."""
    s = name.strip().rstrip(".")
    if not s:
        return 0, 0, 0.0
    parts = [p for p in s.split(".") if p]
    max_lab = max((len(p) for p in parts), default=0)
    digits = sum(1 for c in s if c.isdigit())
    return len(parts), max_lab, digits / max(len(s), 1)


def dns_features_from_qname_series(qnames: pd.Series) -> pd.DataFrame:
    """
    Построить числовые признаки по серии DNS QNAME.

    Параметры
    ----------
    qnames : pd.Series
        Строки имён запроса (например колонка ``dns_qname``).

    Возвращает
    -----------
    pd.DataFrame
        Длина, энтропия, число меток, макс. длина метки, доля цифр (эвристики туннеля).
    """
    q = qnames.fillna("").astype(str)
    stats = q.map(_label_stats)
    return pd.DataFrame(
        {
            "dns_qname_len": q.str.len(),
            "dns_qname_entropy": q.map(_entropy),
            "dns_label_count": stats.map(lambda t: float(t[0])),
            "dns_max_label_len": stats.map(lambda t: float(t[1])),
            "dns_digit_ratio": stats.map(lambda t: float(t[2])),
        }
    )
