# =============================================================================
# Точка входа Streamlit: дашборд кейса 4 (графики, карта, рекомендации).
# Запуск из корня: streamlit run dashboard/app.py
# =============================================================================
"""
Streamlit dashboard (ТЗ): charts, alert list, recommendations.
Run from project root: streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_data_root = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))


def _alerts_json_path() -> Path:
    """Алерты: AppData (frozen CLI), затем соседний ids-cli\\_internal, затем локальный storage."""
    if not getattr(sys, "frozen", False):
        return _data_root / "storage" / "alerts_latest.json"
    la = os.environ.get("LOCALAPPDATA")
    if la:
        shared = Path(la) / "IDS_ML_Project" / "storage" / "alerts_latest.json"
        if shared.is_file():
            return shared
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        from_cli = (
            exe_dir.parent
            / "ids-cli"
            / "_internal"
            / "storage"
            / "alerts_latest.json"
        )
        if from_cli.is_file():
            return from_cli
    return _data_root / "storage" / "alerts_latest.json"

import pandas as pd
import streamlit as st

from dashboard.components.attack_map import attack_map_placeholder
from dashboard.components.recommendations_panel import show_recommendations
from dashboard.components.time_series_charts import alerts_time_series
from dashboard.data_connector import (
    build_incident_report_row,
    dashboard_filter_metadata,
    load_alerts_json,
    load_incidents_jsonl,
    load_retrain_history,
    load_sandbox_reports,
)

st.set_page_config(page_title="IDS ML Console", layout="wide")
st.title("IDS / ML Dashboard")
st.caption(
    "При геокарте по внешним IP данные [DB-IP](https://db-ip.com) (CC BY 4.0) или MaxMind GeoLite2 — см. `python main.py bootstrap` / `config/settings.yaml`."
)

# --- Загрузка последних алертов из JSON (после scripts/03_run_detection_batch.py) ---
alerts_path = _alerts_json_path()
df = load_alerts_json(alerts_path)
is_demo_alert = False
if df.empty:
    df = pd.DataFrame(
        [
            {
                "ip": "10.0.0.1",
                "threat_score": 42.0,
                "recommendation": "Запустите scripts/03_run_detection_batch.py для генерации алертов.",
            }
        ]
    )
    is_demo_alert = True
incidents_path = alerts_path.parent / "incidents.jsonl"
actions_path = alerts_path.parent / "incident_actions.jsonl"
retrain_path = alerts_path.parent / "retrain_history.jsonl"
sandbox_path = alerts_path.parent / "sandbox_reports.jsonl"
inc_df = load_incidents_jsonl(incidents_path)
hist_df = load_retrain_history(retrain_path)
sandbox_df = load_sandbox_reports(sandbox_path)

st.sidebar.header("Фильтры")
meta = dashboard_filter_metadata(df)
statuses = meta["status_options"]
severities = meta["severity_options"]
if meta["status_defaulted"]:
    st.sidebar.info("В алертах не было поля status. Для удобства фильтрации применён status='new' по умолчанию.")
if not severities:
    st.sidebar.info("В текущем наборе алертов нет колонки severity или нет валидных значений — фильтр Severity ограничен.")
selected_status = st.sidebar.multiselect("Статус", statuses, default=statuses if statuses else [])
selected_severity = st.sidebar.multiselect("Severity", severities, default=severities if severities else [])
if meta["single_severity_note"]:
    st.sidebar.info(meta["single_severity_note"])
st.sidebar.caption("Возможные уровни severity: " + " / ".join(meta["severity_levels_all"]))
ip_q = st.sidebar.text_input("IP содержит", value="")
min_score = float(st.sidebar.slider("Минимальный threat score", min_value=0, max_value=100, value=0))

fdf = df.copy()
if selected_status and "status" in fdf.columns:
    fdf = fdf[fdf["status"].astype(str).isin(selected_status)]
if selected_severity and "severity" in fdf.columns:
    fdf = fdf[fdf["severity"].astype(str).isin(selected_severity)]
if ip_q and "ip" in fdf.columns:
    fdf = fdf[fdf["ip"].astype(str).str.contains(ip_q, case=False, na=False)]
if "threat_score" in fdf.columns:
    fdf = fdf[pd.to_numeric(fdf["threat_score"], errors="coerce").fillna(0) >= min_score]

st.caption(f"Алертов после фильтрации: {len(fdf)}")
st.caption("Фильтры в сайдбаре применяются к алертам; блоки online/sandbox ниже используют отдельные журналы истории.")
if is_demo_alert:
    st.warning("Показан демонстрационный алерт: файл alerts пуст. Запустите detect/realtime для реальных данных.")

col1, col2 = st.columns(2)
with col1:
    st.subheader("Временной ряд")
    alerts_time_series(fdf)
with col2:
    attack_map_placeholder(fdf)

st.subheader("Последние алерты")
show_recommendations(fdf)

if not inc_df.empty and "incident_id" in inc_df.columns:
    st.subheader("Карточка инцидента")
    options = inc_df["incident_id"].astype(str).tolist()
    selected_inc = st.selectbox("Выберите incident_id", options, index=0)
    current = inc_df[inc_df["incident_id"].astype(str) == selected_inc].head(1)
    if not current.empty:
        incident = current.iloc[0].to_dict()
        report_row = build_incident_report_row(incident)
        c1, c2, c3 = st.columns(3)
        c1.metric("Threat score", f"{float(report_row.get('threat_score', 0.0)):.2f}")
        c2.metric("Status", str(report_row.get("status", "n/a")))
        c3.metric("Priority", str(report_row.get("priority", "n/a")))
        st.json(report_row)
        report_json = json.dumps(report_row, ensure_ascii=False, indent=2)
        st.download_button(
            "Скачать JSON отчёт инцидента",
            data=report_json,
            file_name=f"{selected_inc}.json",
            mime="application/json",
        )
        st.download_button(
            "Скачать CSV карточки инцидента",
            data=pd.DataFrame([report_row]).to_csv(index=False).encode("utf-8"),
            file_name=f"{selected_inc}.csv",
            mime="text/csv",
        )
    if actions_path.is_file():
        actions_df = pd.DataFrame(load_incidents_jsonl(actions_path))
        if not actions_df.empty and "incident_id" in actions_df.columns:
            st.caption("История действий")
            sub = actions_df[actions_df["incident_id"].astype(str) == selected_inc]
            st.dataframe(sub, use_container_width=True)

st.subheader("Мониторинг после внедрения")
if hist_df.empty:
    st.info("Нет истории retrain (storage/retrain_history.jsonl).")
else:
    if "ts_parsed" in hist_df.columns and "if_baseline_f1" in hist_df.columns:
        st.caption("Метрика графика: if_baseline_f1 (baseline качество IF), это не счётчик rejected.")
        line_df = hist_df.set_index("ts_parsed")[["if_baseline_f1"]].dropna(how="all")
        if not line_df.empty:
            st.line_chart(line_df)
    if "result" in hist_df.columns:
        recent = hist_df.tail(20)
        rejected = (recent["result"].astype(str) == "rejected").sum()
        st.write(f"Последние 20 retrain: rejected={int(rejected)} / {len(recent)}")
        if len(recent) >= 5 and rejected / max(len(recent), 1) > 0.5:
            st.warning("Высокая доля rejected в online retrain — проверьте качество разметки/дрейф данных.")

if sandbox_df.empty:
    st.info("Нет sandbox-отчётов (storage/sandbox_reports.jsonl).")
else:
    cols = [c for c in ("created_parsed", "delta_f1") if c in sandbox_df.columns]
    if len(cols) == 2:
        st.caption("Sandbox график: delta_f1 кандидата относительно baseline.")
        st.line_chart(sandbox_df.set_index("created_parsed")[["delta_f1"]].dropna())
    st.dataframe(
        sandbox_df[[c for c in ("sandbox_run_id", "candidate_model_set_id", "baseline_model_set_id", "decision", "delta_f1", "created_at") if c in sandbox_df.columns]].tail(20),
        use_container_width=True,
    )
