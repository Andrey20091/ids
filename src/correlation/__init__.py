# =============================================================================
# Подпакет correlation: SIEM, правила сопоставления, итоговый threat score.
# =============================================================================
"""Correlation: SIEM events, rules, threat scoring."""

from src.correlation.threat_scoring import score_alert

__all__ = ["score_alert"]
