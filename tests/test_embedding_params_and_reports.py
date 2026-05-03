import importlib.util
import os
import sys
from pathlib import Path

import pandas as pd
import yaml


def _load_train_script():
    root = Path(__file__).resolve().parents[1]
    path = root / "scripts" / "02_train_all.py"
    spec = importlib.util.spec_from_file_location("train_script_mod", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(mod)
    return mod, path


def test_embedding_hyperparams_are_read_from_settings(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "processed").mkdir(parents=True, exist_ok=True)
    settings = {
        "paths": {"artifacts": "artifacts", "storage": "storage"},
        "aggregation": {"resample_freq": "1min", "syn_spike_multiplier": 3.0},
        "pipeline": {"l2_only_after_l1": True},
        "online": {
            "retrain_interval_minutes": 15,
            "min_samples_retrain": 10,
            "validation_size_ratio": 0.2,
            "if_accept_equal_f1": True,
            "retrain_deep_models": False,
            "deep_validation": {"enabled": True},
        },
        "models": {
            "random_forest": {"n_estimators": 10, "max_depth": 4, "random_state": 42},
            "isolation_forest": {"n_estimators": 10, "contamination": 0.1, "random_state": 42},
            "autoencoder": {"encoding_dim": 8, "epochs": 1, "batch_size": 8, "learning_rate": 0.001},
            "lstm": {"hidden_size": 8, "sequence_length": 3, "epochs": 1, "batch_size": 8, "learning_rate": 0.001},
            "embedding": {
                "epochs": 7,
                "hidden_size": 19,
                "embed_dim": 11,
                "batch_size": 13,
                "learning_rate": 0.009,
                "random_state": 321,
            },
            "raw_header_cnn": {"epochs": 1, "batch_size": 8, "learning_rate": 0.001},
        },
    }
    (tmp_path / "config" / "settings.yaml").write_text(yaml.safe_dump(settings, sort_keys=False), encoding="utf-8")
    feat = {
        "header_raw_bytes": {"enabled": False},
        "numeric_features": ["f1", "f2"],
        "categorical_for_embedding": {"protocol_column": "Protocol", "port_column": "Destination Port"},
        "label_column": "Label",
        "timestamp_column": "Timestamp",
    }
    (tmp_path / "config" / "feature_columns.yaml").write_text(yaml.safe_dump(feat, sort_keys=False), encoding="utf-8")
    pd.DataFrame(
        {
            "f1": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
            "f2": [0.1, 0.2, 0.3, 0.4, 0.5, 0.6],
            "Protocol": [6, 6, 17, 17, 6, 17],
            "Destination Port": [80, 80, 443, 53, 80, 53],
            "Timestamp": pd.date_range("2026-01-01", periods=6, freq="min").astype(str),
            "Label": ["BENIGN", "Attack", "BENIGN", "Attack", "BENIGN", "Attack"],
            "is_attack": [0, 1, 0, 1, 0, 1],
        }
    ).to_csv(tmp_path / "data" / "processed" / "flows.csv", index=False)

    old_root = os.environ.get("IDS_PROJECT_ROOT")
    os.environ["IDS_PROJECT_ROOT"] = str(tmp_path)
    mod, script_path = _load_train_script()
    captured = {}

    monkeypatch.setattr("src.models.train_autoencoder.train_autoencoder", lambda *a, **k: {"model_path": "x"})
    monkeypatch.setattr("src.models.train_lstm.train_lstm", lambda *a, **k: {"model_path": "x", "val_f1": 0.8})
    monkeypatch.setattr("src.models.train_raw_header_cnn.train_raw_header_cnn", lambda *a, **k: {"model_path": "x"})

    def _fake_emb(*_a, **kwargs):
        captured.update(kwargs)
        return {"path": "x", "train_acc": 0.9, "val_acc": 0.85}

    monkeypatch.setattr("src.models.train_embedding_classifier.train_embedding_classifier", _fake_emb)

    old_argv = sys.argv[:]
    try:
        sys.argv = [str(script_path), "--data", str(tmp_path / "data" / "processed" / "flows.csv")]
        mod.main()
    finally:
        sys.argv = old_argv
        if old_root is None:
            os.environ.pop("IDS_PROJECT_ROOT", None)
        else:
            os.environ["IDS_PROJECT_ROOT"] = old_root

    assert captured["epochs"] == 7
    assert captured["hidden"] == 19
    assert captured["embed_dim"] == 11
    assert captured["batch_size"] == 13
    assert abs(float(captured["learning_rate"]) - 0.009) < 1e-12
    assert captured["random_state"] == 321
