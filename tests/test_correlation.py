# =============================================================================
# Тесты: корреляция с SIEM и итоговый threat_score.
# =============================================================================
import pandas as pd

from src.correlation.threat_scoring import score_alert


def test_threat_score_boost():
    """SIEM failed_login повышает итоговый threat_score относительно сетевого скора."""
    siem = pd.DataFrame(
        {
            "ip": ["1.1.1.1", "1.1.1.1"],
            "event_type": ["failed_login", "failed_login"],
        }
    )
    r = score_alert("1.1.1.1", 0.8, siem)
    assert r["threat_score"] >= 80
    assert "recommendation" in r
