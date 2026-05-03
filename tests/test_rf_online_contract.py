import json
from pathlib import Path

import joblib
import pandas as pd

from src.online.retrain_scheduler import run_one_retrain_iteration
from src.pipeline.level2_deep import random_forest_predict_proba


def test_online_rf_updates_model_and_label_encoder_consistently(tmp_path, monkeypatch):
    n = 80
    data_path = tmp_path / "flows.csv"
    df = pd.DataFrame(
        {
            "f1": [float(i % 10) for i in range(n)],
            "f2": [float((i * 2) % 7) for i in range(n)],
            "Timestamp": pd.date_range("2026-01-01", periods=n, freq="min").astype(str),
            "is_attack": [1 if i % 5 == 0 else 0 for i in range(n)],
        }
    )
    df.to_csv(data_path, index=False)

    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "config" / "feature_columns.yaml").write_text(
        json.dumps(
            {
                "numeric_features": ["f1", "f2"],
                "timestamp_column": "Timestamp",
                "header_raw_bytes": {"enabled": False},
            }
        ),
        encoding="utf-8",
    )

    settings = {
        "paths": {"artifacts": str(tmp_path / "artifacts"), "storage": str(tmp_path / "storage")},
        "online": {
            "retrain_interval_minutes": 15,
            "min_samples_retrain": 10,
            "validation_size_ratio": 0.2,
            "if_accept_equal_f1": True,
            "retrain_deep_models": False,
            "deep_validation": {"enabled": True},
        },
        "aggregation": {"resample_freq": "1min"},
        "models": {
            "isolation_forest": {"n_estimators": 10, "contamination": 0.1, "random_state": 42},
            "random_forest": {"n_estimators": 20, "max_depth": 6, "random_state": 42},
        },
    }
    monkeypatch.setenv("IDS_PROJECT_ROOT", str(tmp_path))
    monkeypatch.setattr("src.online.retrain_scheduler.load_settings", lambda: settings)

    out = run_one_retrain_iteration(data_path, artifacts_dir=settings["paths"]["artifacts"])
    assert out["status"] in ("ok", "rejected")

    art = Path(settings["paths"]["artifacts"])
    assert (art / "rf_model.joblib").is_file()
    assert (art / "rf_label_encoder.joblib").is_file()
    le = joblib.load(art / "rf_label_encoder.joblib")
    assert set(map(str, le.classes_)).issuperset({"BENIGN", "ATTACK"})

    X = df[["f1", "f2"]]
    pred = random_forest_predict_proba(X, art / "rf_model.joblib", art / "rf_label_encoder.joblib")
    assert "l2_rf_attack_score" in pred.columns
    assert float(pred["l2_rf_attack_score"].min()) >= 0.0
    assert float(pred["l2_rf_attack_score"].max()) <= 1.0
