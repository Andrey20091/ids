# =============================================================================
# Компонент дашборда: логическая «карта» источников по октетам IP (кейс 4).
# =============================================================================
"""Attack map: geo map when coords are available, otherwise logical topology."""

from __future__ import annotations

import pandas as pd
import streamlit as st


def _plotly_chart(fig) -> None:
    try:
        st.plotly_chart(fig, width="stretch")
    except TypeError:
        st.plotly_chart(fig, use_container_width=True)


def _ip_to_xy(ip: str) -> tuple[float, float]:
    """Преобразовать IPv4 в координаты (подсеть / хост) для визуализации."""
    parts = str(ip).split(".")
    if len(parts) >= 4 and all(p.isdigit() for p in parts[:4]):
        a, b, c, d = [int(p) for p in parts[:4]]
        # A*256+B и C*256+D сохраняют смысл "сегмент/хост-пул" без коллизий A*10+B.
        return float(a * 256 + b), float(c * 256 + d)
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return float(parts[0]), float(parts[1])
    return 0.0, 0.0


def _apply_ip_jitter(plot_df: pd.DataFrame) -> pd.DataFrame:
    """Добавить небольшой детерминированный offset для совпадающих IP."""
    out = plot_df.copy()
    grp = out.groupby("ip", dropna=False)
    out["_dup_rank"] = grp.cumcount()
    out["_dup_size"] = grp["ip"].transform("size")
    out["_jitter"] = (out["_dup_rank"] - (out["_dup_size"] - 1) / 2.0) * 0.12
    out["map_x"] = out["map_x"] + out["_jitter"]
    out["map_y"] = out["map_y"] + out["_jitter"]
    return out


def attack_map_placeholder(alerts_df: pd.DataFrame) -> None:
    """
    Отобразить «карту» алертов: оси — производные от октетов IP, размер — threat_score.

    Не геолокация, а логическая топология сегментов (как допустимый учебный прототип ТЗ).
    """
    st.subheader("Карта источников атак")
    if alerts_df.empty or "ip" not in alerts_df.columns:
        st.info("Нет данных IP для отображения.")
        return
    try:
        import plotly.express as px
    except ImportError:
        counts = alerts_df.groupby("ip").size().reset_index(name="alerts")
        st.bar_chart(counts.set_index("ip"))
        return

    plot_df = alerts_df.copy()
    if {"latitude", "longitude"}.issubset(plot_df.columns):
        geo = plot_df.dropna(subset=["latitude", "longitude"]).copy()
        if not geo.empty:
            fig = px.scatter_geo(
                geo,
                lat="latitude",
                lon="longitude",
                color="threat_score" if "threat_score" in geo.columns else None,
                hover_name="ip",
                title="География источников атак",
            )
            _plotly_chart(fig)
            return

    st.caption(
        "Geo-координаты отсутствуют (нужен MMDB: `python main.py bootstrap` или `geoip.city_db`); "
        "ниже — логическая топология IP."
    )
    xy = plot_df["ip"].map(_ip_to_xy)
    plot_df["map_x"] = [t[0] for t in xy]
    plot_df["map_y"] = [t[1] for t in xy]
    ip_unique = int(plot_df["ip"].astype(str).nunique(dropna=True))
    if ip_unique <= 1:
        st.warning("Все алерты относятся к одному IP/сегменту. Это корректно для текущих данных.")
    mode = st.radio(
        "Режим отображения",
        ["По сегменту/хост-пулу", "По полному IP (jitter)"],
        horizontal=True,
    )
    if mode == "По полному IP (jitter)":
        plot_df = _apply_ip_jitter(plot_df)
    score_col = "threat_score" if "threat_score" in plot_df.columns else None
    fig = px.scatter(
        plot_df,
        x="map_x",
        y="map_y",
        color=score_col,
        hover_data=["ip"] + ([score_col] if score_col else []),
        labels={"map_x": "Сегмент (A*256+B)", "map_y": "Хост-пул (C*256+D)"},
        title="Распределение алертов по адресному пространству",
        opacity=0.75,
    )
    _plotly_chart(fig)
    top_n = (
        plot_df.groupby("ip", dropna=False)
        .size()
        .reset_index(name="alerts")
        .sort_values("alerts", ascending=False)
        .head(5)
    )
    if not top_n.empty:
        st.caption("Топ IP по числу алертов")
        st.dataframe(top_n, use_container_width=True, hide_index=True)
