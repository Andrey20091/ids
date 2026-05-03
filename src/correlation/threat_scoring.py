# =============================================================================
# Скоринг угрозы и рекомендации по реагированию (кейс 4 + SIEM-корреляция).
# =============================================================================
"""Threat rating + response recommendations (ТЗ)."""

from __future__ import annotations

import pandas as pd

from src.correlation.correlation_rules import match_siem_for_ip
from src.utils_config import load_settings


def score_alert(
    client_ip: str,
    network_score: float,
    siem_df: pd.DataFrame,
) -> dict:
    """
    Объединить сетевой скор (ML/L2) с событиями SIEM и выдать итог и рекомендацию.

    Параметры
    ----------
    client_ip : str
        IP источника из алерта.
    network_score : float
        Оценка из сетевых моделей (обычно 0–1 или уже в масштабе 0–100).
    siem_df : pd.DataFrame
        Таблица событий SIEM (см. ``load_siem_events``).

    Возвращает
    -----------
    dict
        ``ip``, ``threat_score``, счётчики SIEM, текст ``recommendation``.
    """
    settings = load_settings()
    boost_auth = settings["threat_scoring"]["siem_boost_failed_auth"]
    boost_cfg = settings["threat_scoring"]["siem_boost_config_change"]

    # --- Сопоставление IP с типами событий SIEM (failed_login, config_change, …) ---
    siem_sig = match_siem_for_ip(siem_df, client_ip)
    ns = float(network_score)
    # network_score expected in [0,1] (e.g. RF attack probability); scale to 0–100
    score = 100.0 * ns if ns <= 1.0 else min(ns, 100.0)
    score += siem_sig.get("failed_login", 0) * boost_auth
    score += siem_sig.get("config_change", 0) * boost_cfg
    score = min(100.0, score)

    failed_login = int(siem_sig.get("failed_login", 0))
    config_change = int(siem_sig.get("config_change", 0))
    has_siem_signal = failed_login > 0 or config_change > 0

    if score >= 90:
        severity = "Emergency"
        rec = (
            "Emergency: block source IP immediately, isolate impacted host/segment, "
            "and escalate incident to on-call security lead."
        )
    elif score >= 80:
        severity = "Critical"
        rec = (
            "Critical: block source IP at perimeter firewall and start containment; "
            "collect endpoint/network evidence for incident response."
        )
    elif score >= 65:
        severity = "High"
        rec = (
            "High: tighten monitoring, validate SIEM events, and prepare rapid containment "
            "playbook if activity continues."
        )
    elif score >= 50:
        severity = "Medium"
        rec = (
            "Medium: open analyst review ticket, inspect source/destination context, "
            "and keep traffic under enhanced observation."
        )
    elif score >= 30:
        severity = "Low"
        rec = (
            "Low: add source to watchlist and monitor recurrence across time windows."
            if has_siem_signal
            else "Low: monitor and log; weak threat signals, no immediate containment required."
        )
    else:
        severity = "Info"
        rec = "Info: keep telemetry only; likely benign or scan noise at current confidence."

    return {
        "ip": client_ip,
        "threat_score": round(score, 2),
        "severity": severity,
        "siem_failed_login": failed_login,
        "siem_config_change": config_change,
        "recommendation": rec,
    }
