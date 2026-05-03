import pandas as pd

from src.online.retrain_scheduler import run_one_retrain_iteration


def test_online_retrain_returns_deep_report_when_disabled(tmp_path, monkeypatch):
    data_path = tmp_path / "flows.csv"
    n = 40
    df = pd.DataFrame(
        {
            "f1": [float(i) for i in range(n)],
            "f2": [float(i % 7) for i in range(n)],
            "is_attack": [1 if i % 5 == 0 else 0 for i in range(n)],
        }
    )
    df.to_csv(data_path, index=False)

    settings = {
        "paths": {"artifacts": str(tmp_path / "artifacts")},
        "online": {
            "min_samples_retrain": 10,
            "validation_size_ratio": 0.2,
            "if_accept_equal_f1": True,
            "retrain_deep_models": False,
        },
        "models": {
            "isolation_forest": {"n_estimators": 10, "contamination": 0.1},
            "random_forest": {"n_estimators": 10, "max_depth": 4, "random_state": 42},
        },
    }
    monkeypatch.setattr("src.online.retrain_scheduler.load_settings", lambda: settings)

    result = run_one_retrain_iteration(data_path, artifacts_dir=settings["paths"]["artifacts"])
    assert result["status"] == "ok"
    assert "deep_models" in result
    assert result["deep_models"]["status"] == "skipped"
