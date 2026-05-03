# =============================================================================
# Тесты: training_profiles, инварианты is_attack, применение профиля обучения.
# =============================================================================
from __future__ import annotations

import copy

import pandas as pd
import yaml

from src.utils.pipeline_validate import apply_training_profile, validate_prepared_flows


def test_apply_training_profile_development_changes_rf():
    base = {
        "models": {
            "random_forest": {"n_estimators": 200, "max_depth": 24},
            "isolation_forest": {"n_estimators": 200},
        },
        "training_profiles": {
            "development": {
                "random_forest": {"n_estimators": 80},
            },
        },
    }
    out = apply_training_profile(copy.deepcopy(base), "development")
    assert out["models"]["random_forest"]["n_estimators"] == 80
    assert out["models"]["random_forest"]["max_depth"] == 24
    assert out["models"]["isolation_forest"]["n_estimators"] == 200


def test_apply_training_profile_production_is_clone():
    base = {"models": {"random_forest": {"n_estimators": 5}}}
    out = apply_training_profile(base, "production")
    assert out["models"]["random_forest"]["n_estimators"] == 5
    out["models"]["random_forest"]["n_estimators"] = 999
    assert base["models"]["random_forest"]["n_estimators"] == 5


def test_validate_prepared_flows_is_attack_mismatch():
    df = pd.DataFrame(
        {
            "Label": ["BENIGN", "FTP-Patator"],
            "is_attack": [1, 0],
        }
    )
    feat = {"label_column": "Label", "header_raw_bytes": {"enabled": False}}
    w = validate_prepared_flows(df, feat)
    assert any("is_attack" in x for x in w)


def test_validate_prepared_flows_zero_hb_warning():
    """hb_* включены в конфиге — нули должны давать предупреждение."""
    feat = {
        "label_column": "Label",
        "header_raw_bytes": {"enabled": True, "max_packets": 2, "bytes_per_packet": 2, "column_prefix": "hb_"},
        "numeric_features": ["hb_0", "hb_1", "hb_2", "hb_3"],
    }
    df = pd.DataFrame(
        {
            "Label": ["BENIGN"],
            "is_attack": [0],
            "hb_0": [0.0],
            "hb_1": [0.0],
            "hb_2": [0.0],
            "hb_3": [0.0],
        }
    )
    w = validate_prepared_flows(df, feat)
    assert len(w) >= 1 and any("CNN" in msg or "нул" in msg.lower() for msg in w)
