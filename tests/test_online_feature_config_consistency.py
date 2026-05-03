from pathlib import Path

import pandas as pd

from src.online.retrain_scheduler import run_one_retrain_iteration


def test_online_retrain_uses_merged_feature_config(tmp_path, monkeypatch):
    data_path = tmp_path / "flows.csv"
    pd.DataFrame(
        {
            "Total Length of Fwd Packets": [1.0, 2.0, 3.0, 4.0],
            "is_attack": [0, 1, 0, 1],
            "Timestamp": pd.date_range("2026-01-01", periods=4, freq="min").astype(str),
        }
    ).to_csv(data_path, index=False)

    called = {"ok": False}

    def _fake_feat(_path):
        called["ok"] = True
        return {
            "numeric_features": ["Total Length of Fwd Packets"],
            "label_column": "Label",
            "timestamp_column": "Timestamp",
            "categorical_for_embedding": {},
        }

    settings = {
        "paths": {"artifacts": str(tmp_path / "artifacts"), "storage": str(tmp_path / "storage")},
        "online": {
            "retrain_interval_minutes": 15,
            "min_samples_retrain": 3,
            "validation_size_ratio": 0.2,
            "if_accept_equal_f1": True,
            "retrain_deep_models": False,
            "deep_validation": {"enabled": True},
        },
        "models": {
            "isolation_forest": {"n_estimators": 10, "contamination": 0.2},
            "random_forest": {"n_estimators": 10, "max_depth": 4, "random_state": 42},
        },
    }
    monkeypatch.setattr("src.online.retrain_scheduler.load_settings", lambda: settings)
    monkeypatch.setattr("src.online.retrain_scheduler.project_root", lambda: tmp_path)
    monkeypatch.setattr("src.online.retrain_scheduler.load_merged_feature_config", _fake_feat)
    monkeypatch.setattr("src.online.retrain_scheduler.write_model_status_report", lambda *_a, **_k: Path("x"))

    out = run_one_retrain_iteration(data_path, artifacts_dir=settings["paths"]["artifacts"])
    assert called["ok"] is True
    assert out["status"] in ("ok", "rejected")
