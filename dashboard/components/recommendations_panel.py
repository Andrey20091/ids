# =============================================================================
# Панель рекомендаций по алертам (ТЗ: блокировка IP, изоляция сегмента).
# =============================================================================
"""Recommendations panel (ТЗ)."""

from __future__ import annotations

import pandas as pd
import streamlit as st


def show_recommendations(df: pd.DataFrame) -> None:
    """
    Показать таблицу последних алертов с IP, скором и текстом рекомендации.

    Параметры
    ----------
    df : pd.DataFrame
        Алерты из ``storage/alerts_latest.json`` или заглушка.
    """
    if df.empty:
        st.warning("Нет алертов.")
        return
    display_cols = [
        c
        for c in ("incident_id", "status", "owner", "ip", "severity", "threat_score", "recommendation")
        if c in df.columns
    ]
    st.dataframe(df[display_cols].head(50), use_container_width=True)
