# =============================================================================
# Временные ряды угроз по полю ts в алертах (кейс 4, дашборд).
# =============================================================================
"""Time series charts (ТЗ)."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st


def _plotly_chart(fig) -> None:
    try:
        st.plotly_chart(fig, width="stretch")
    except TypeError:
        st.plotly_chart(fig, use_container_width=True)


def demo_time_series() -> None:
    """Детерминированный placeholder, если в алертах нет времени."""
    st.warning("DEMO PLACEHOLDER: в алертах нет валидной колонки времени `ts`.")
    t = list(range(12))
    y = [10, 12, 11, 13, 12, 14, 13, 15, 14, 16, 15, 17]
    fig = px.line(x=t, y=y, labels={"x": "Слот времени", "y": "Индикатор (demo)"})
    _plotly_chart(fig)


def _auto_bucket_freq(ts: pd.Series) -> str:
    """Автовыбор шага агрегации: минута для короткого окна, иначе час."""
    if ts.empty:
        return "h"
    span = ts.max() - ts.min()
    # Короткие демо-прогоны обычно укладываются в минуты — часовая агрегация даёт 1 точку.
    if span <= pd.Timedelta(hours=2):
        return "min"
    return "h"


def alerts_time_series(alerts_df: pd.DataFrame) -> None:
    """
    Построить средний threat_score по часам, если есть поле ``ts``.

    Параметры
    ----------
    alerts_df : pd.DataFrame
        Алерты из JSON; ожидается колонка ``ts`` (строка времени).
    """
    if alerts_df.empty or "ts" not in alerts_df.columns:
        demo_time_series()
        return
    sub = alerts_df.dropna(subset=["ts"]).copy()
    if sub.empty:
        demo_time_series()
        return
    sub["ts_parsed"] = pd.to_datetime(sub["ts"], errors="coerce", utc=True).dt.tz_localize(None)
    sub = sub.dropna(subset=["ts_parsed"])
    if sub.empty:
        demo_time_series()
        return
    if "threat_score" not in sub.columns:
        sub["threat_score"] = 0.0
    freq = _auto_bucket_freq(sub["ts_parsed"])
    hourly = sub.groupby(sub["ts_parsed"].dt.floor(freq))["threat_score"].mean().reset_index()
    hourly.columns = ["hour", "mean_threat"]
    st.caption(f"Агрегация ряда: {'по минутам' if freq == 'min' else 'по часам'}")
    fig = px.line(
        hourly,
        x="hour",
        y="mean_threat",
        labels={"hour": "Время", "mean_threat": "Средний threat score"},
        markers=True,
    )
    _plotly_chart(fig)
