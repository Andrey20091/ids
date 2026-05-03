# =============================================================================
# Загрузка алертов для дашборда из JSON.
# =============================================================================
"""Read alerts/incidents/retrain history for dashboard views."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.governance.storage import load_jsonl

SEVERITY_LEVELS = ("Info", "Low", "Medium", "High", "Critical", "Emergency")


def _severity_from_score(score: float) -> str:
    if score >= 90:
        return "Emergency"
    if score >= 80:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 50:
        return "Medium"
    if score >= 30:
        return "Low"
    return "Info"


def load_alerts_json(path: str | Path) -> pd.DataFrame:
    """
    Прочитать ``alerts_latest.json`` и вернуть таблицу.

    Параметры
    ----------
    path : str | Path
        Путь к JSON-массиву объектов алертов.

    Возвращает
    -----------
    pd.DataFrame
        Пустой датафрейм, если файла нет.
    """
    p = Path(path)
    if not p.is_file():
        return pd.DataFrame()
    try:
        raw = p.read_text(encoding="utf-8").strip()
    except OSError:
        return pd.DataFrame()
    if not raw:
        return pd.DataFrame()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return pd.DataFrame()
    if not isinstance(data, list):
        return pd.DataFrame()
    alerts = pd.DataFrame(data)
    if alerts.empty:
        return alerts
    if "status" not in alerts.columns:
        alerts["status"] = "new"
        alerts["_status_defaulted"] = True
    else:
        alerts["_status_defaulted"] = False
    if "severity" not in alerts.columns and "threat_score" in alerts.columns:
        score = pd.to_numeric(alerts["threat_score"], errors="coerce").fillna(0.0)
        alerts["severity"] = score.map(lambda v: _severity_from_score(float(v)))

    incidents_path = p.parent / "incidents.jsonl"
    incidents = pd.DataFrame(load_jsonl(incidents_path))
    if incidents.empty:
        return alerts

    join_cols = [c for c in ("ip", "ts", "threat_score") if c in alerts.columns and c in incidents.columns]
    if not join_cols:
        return alerts
    keep_cols = join_cols + [c for c in ("incident_id", "status", "owner") if c in incidents.columns]
    merged = alerts.merge(
        incidents[keep_cols].drop_duplicates(),
        on=join_cols,
        how="left",
        suffixes=("", "_inc"),
    )
    if "status_inc" in merged.columns:
        merged["status"] = merged["status_inc"].where(merged["status_inc"].notna(), merged["status"])
        merged = merged.drop(columns=["status_inc"])
    if "owner_inc" in merged.columns:
        if "owner" in merged.columns:
            merged["owner"] = merged["owner_inc"].where(merged["owner_inc"].notna(), merged["owner"])
        else:
            merged["owner"] = merged["owner_inc"]
        merged = merged.drop(columns=["owner_inc"])
    return merged


def dashboard_filter_metadata(alerts: pd.DataFrame) -> dict:
    """Sidebar-friendly metadata for status/severity filters and UX hints."""
    if alerts is None or alerts.empty:
        return {
            "status_options": ["new"],
            "severity_options": [],
            "severity_levels_all": list(SEVERITY_LEVELS),
            "status_defaulted": False,
            "single_severity_note": "",
        }
    statuses = sorted([str(x) for x in alerts.get("status", pd.Series(dtype=str)).dropna().unique()])
    if not statuses:
        statuses = ["new"]
    sev_set = set(alerts["severity"].astype(str).dropna()) if "severity" in alerts.columns else set()
    severities = [s for s in SEVERITY_LEVELS if s in sev_set]
    note = ""
    if len(severities) == 1:
        note = f"В текущем наборе данных присутствует только один уровень severity: {severities[0]}."
    status_defaulted = bool(alerts.get("_status_defaulted", pd.Series([False])).any())
    return {
        "status_options": statuses,
        "severity_options": severities,
        "severity_levels_all": list(SEVERITY_LEVELS),
        "status_defaulted": status_defaulted,
        "single_severity_note": note,
    }


def load_incidents_jsonl(path: str | Path) -> pd.DataFrame:
    """Load incidents JSONL as dataframe."""
    rows = load_jsonl(Path(path))
    return pd.DataFrame(rows) if rows else pd.DataFrame()


def load_retrain_history(path: str | Path) -> pd.DataFrame:
    """Load retrain history JSONL."""
    rows = load_jsonl(Path(path))
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if "ts" in df.columns:
        df["ts_parsed"] = pd.to_datetime(df["ts"], errors="coerce", utc=True).dt.tz_localize(None)
    return df


def load_sandbox_reports(path: str | Path) -> pd.DataFrame:
    """Load sandbox reports JSONL."""
    rows = load_jsonl(Path(path))
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if "created_at" in df.columns:
        df["created_parsed"] = pd.to_datetime(df["created_at"], errors="coerce", utc=True).dt.tz_localize(None)
    if "metrics" in df.columns:
        def _delta(m: object) -> float:
            if isinstance(m, dict):
                return float(m.get("delta_f1", 0.0) or 0.0)
            return 0.0
        df["delta_f1"] = df["metrics"].map(_delta)
    return df


def build_incident_report_row(incident: dict) -> dict:
    """Normalize selected incident for export/reporting."""
    signal = incident.get("signal", {}) if isinstance(incident.get("signal"), dict) else {}
    siem = incident.get("siem", {}) if isinstance(incident.get("siem"), dict) else {}
    return {
        "incident_id": incident.get("incident_id"),
        "created_at": incident.get("created_at"),
        "updated_at": incident.get("updated_at"),
        "status": incident.get("status"),
        "priority": incident.get("priority"),
        "owner": incident.get("owner"),
        "ip": incident.get("ip"),
        "ts": incident.get("ts"),
        "threat_score": incident.get("threat_score"),
        "recommendation": incident.get("recommendation"),
        "siem_failed_login": siem.get("failed_login", 0),
        "siem_config_change": siem.get("config_change", 0),
        "l1_triggered": signal.get("l1_triggered", False),
        "l2_rf_attack_score": signal.get("l2_rf_attack_score", 0.0),
        "l2_ae_ratio": signal.get("l2_ae_ratio", 0.0),
        "l2_lstm_attack_score": signal.get("l2_lstm_attack_score", 0.0),
        "l2_emb_attack_score": signal.get("l2_emb_attack_score", 0.0),
    }
