import pandas as pd

from dashboard.components.attack_map import _apply_ip_jitter, _ip_to_xy, attack_map_placeholder
from dashboard.components.recommendations_panel import show_recommendations
from dashboard.components.time_series_charts import _auto_bucket_freq, alerts_time_series


def test_alerts_time_series_handles_missing_ts():
    df = pd.DataFrame([{"ip": "1.1.1.1", "threat_score": 10.0}])
    alerts_time_series(df)


def test_auto_bucket_freq_short_span_uses_minutes():
    ts = pd.to_datetime(["2026-01-01 10:00:00", "2026-01-01 10:30:00"])
    assert _auto_bucket_freq(pd.Series(ts)) == "min"


def test_auto_bucket_freq_long_span_uses_hours():
    ts = pd.to_datetime(["2026-01-01 10:00:00", "2026-01-01 16:30:00"])
    assert _auto_bucket_freq(pd.Series(ts)) == "h"


def test_attack_map_handles_empty_and_partial():
    attack_map_placeholder(pd.DataFrame())
    attack_map_placeholder(pd.DataFrame([{"ip": "1.1.1.1", "threat_score": 55.0}]))
    attack_map_placeholder(
        pd.DataFrame(
            [
                {
                    "ip": "2.2.2.2",
                    "threat_score": 60.0,
                    "latitude": 55.75,
                    "longitude": 37.61,
                }
            ]
        )
    )


def test_recommendations_panel_handles_columns_subset():
    show_recommendations(pd.DataFrame())
    show_recommendations(pd.DataFrame([{"ip": "1.1.1.1", "recommendation": "watch"}]))


def test_ip_projection_avoids_segment_collision():
    x1, y1 = _ip_to_xy("10.0.0.1")
    x2, y2 = _ip_to_xy("9.10.0.1")
    assert x1 != x2
    assert y1 == y2


def test_ip_jitter_splits_duplicate_points():
    base = pd.DataFrame(
        [
            {"ip": "10.0.0.1", "map_x": 2560.0, "map_y": 1.0},
            {"ip": "10.0.0.1", "map_x": 2560.0, "map_y": 1.0},
            {"ip": "10.0.0.1", "map_x": 2560.0, "map_y": 1.0},
        ]
    )
    out = _apply_ip_jitter(base)
    assert out["map_x"].nunique() == 3
    assert out["map_y"].nunique() == 3
