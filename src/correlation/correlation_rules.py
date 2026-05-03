# =============================================================================
# Правила корреляции: сопоставление IP с типами событий SIEM (кейс 4).
# =============================================================================
"""Correlate network alerts with SIEM rows (ТЗ)."""

from __future__ import annotations

import pandas as pd


def match_siem_for_ip(
    siem_df: pd.DataFrame,
    client_ip: str,
    window_events: list[str] | None = None,
) -> pd.Series:
    """
    Агрегировать по IP число событий каждого типа из ``window_events``.

    Ожидаемые колонки в ``siem_df``: ``ip``, ``event_type``; ``severity`` опционально.
    """
    if window_events is None:
        window_events = ["failed_login", "config_change", "new_user"]
    # --- Фильтр по клиентскому IP и подсчёт по типам ---
    sub = siem_df[siem_df["ip"] == client_ip]
    counts = {e: int((sub["event_type"] == e).sum()) for e in window_events}
    return pd.Series(counts)
