import json
import os
import subprocess
import sys
from pathlib import Path

import pandas as pd
import yaml

from src.utils.model_health import hb_signal_quality


def _write_min_settings(path: Path) -> None:
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
            "deep_validation": {
                "enabled": True,
                "ae_max_val_mse_ratio": 1.12,
                "lstm_min_val_f1_vs_baseline": -0.02,
                "embedding_min_val_acc_vs_baseline": -0.02,
            },
        },
        "models": {
            "random_forest": {"n_estimators": 20, "max_depth": 8, "random_state": 42},
            "isolation_forest": {"n_estimators": 20, "contamination": 0.1, "random_state": 42},
            "autoencoder": {"encoding_dim": 8, "epochs": 1, "batch_size": 16, "learning_rate": 0.001},
            "lstm": {"hidden_size": 8, "sequence_length": 3, "epochs": 1, "batch_size": 8, "learning_rate": 0.001},
            "embedding": {
                "epochs": 2,
                "hidden_size": 16,
                "embed_dim": 8,
                "batch_size": 8,
                "learning_rate": 0.005,
                "random_state": 123,
            },
            "raw_header_cnn": {"epochs": 1, "batch_size": 8, "learning_rate": 0.001},
        },
    }
    path.write_text(yaml.safe_dump(settings, sort_keys=False, allow_unicode=False), encoding="utf-8")


def _write_min_features(path: Path) -> None:
    feat = {
        "header_raw_bytes": {"enabled": True, "max_packets": 1, "bytes_per_packet": 4, "column_prefix": "hb_"},
        "numeric_features": ["f1", "f2", "SYN Flag Count"],
        "categorical_for_embedding": {"protocol_column": "Protocol", "port_column": "Destination Port"},
        "label_column": "Label",
        "timestamp_column": "Timestamp",
    }
    path.write_text(yaml.safe_dump(feat, sort_keys=False, allow_unicode=False), encoding="utf-8")


def test_train_generates_train_and_model_status_reports(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "processed").mkdir(parents=True, exist_ok=True)
    (tmp_path / "storage").mkdir(parents=True, exist_ok=True)
    _write_min_settings(tmp_path / "config" / "settings.yaml")
    _write_min_features(tmp_path / "config" / "feature_columns.yaml")

    n = 80
    df = pd.DataFrame(
        {
            "f1": [float(i % 10) for i in range(n)],
            "f2": [float((i * 3) % 7) for i in range(n)],
            "SYN Flag Count": [float(i % 5) for i in range(n)],
            "Protocol": [6 if i % 2 == 0 else 17 for i in range(n)],
            "Destination Port": [80 if i % 2 == 0 else 443 for i in range(n)],
            "Timestamp": pd.date_range("2026-01-01", periods=n, freq="min").astype(str),
            "Label": ["BENIGN" if i % 3 else "Attack" for i in range(n)],
            "is_attack": [0 if i % 3 else 1 for i in range(n)],
            "hb_0": [0.0] * n,
            "hb_1": [0.0] * n,
            "hb_2": [0.0] * n,
            "hb_3": [0.0] * n,
        }
    )
    data_path = tmp_path / "data" / "processed" / "flows.csv"
    df.to_csv(data_path, index=False)

    env = dict(os.environ)
    env["IDS_PROJECT_ROOT"] = str(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "02_train_all.py"), "--data", str(data_path), "--skip-torch"],
        cwd=root,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr

    reports = sorted((tmp_path / "storage" / "train_reports").glob("train_report_*.json"))
    assert reports, "train report was not generated"
    tr = json.loads(reports[-1].read_text(encoding="utf-8"))
    assert tr["dataset_rows"] == n
    assert "dataset_tag" in tr
    assert "dataset_source" in tr
    assert "train_mode" in tr
    assert "policy_decision" in tr
    assert "config_hash" in tr and tr["config_hash"]
    assert "rf" in tr["models"] and "if_flow" in tr["models"]
    assert "hb_signal_quality" in tr
    assert tr["models"]["raw_header_cnn"]["detect_participation_ready"] is False

    status_path = tmp_path / "storage" / "model_status_report.json"
    assert status_path.is_file()
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert "models" in status and len(status["models"]) >= 5
    assert "online_outcome_global" in status
    assert "usage_parse_error" in status
    for row in status["models"]:
        assert "last_online_outcome" in row


def test_hb_signal_quality_detects_constant_signal() -> None:
    df_const = pd.DataFrame({"hb_0": [0.0, 0.0], "hb_1": [0.0, 0.0]})
    q1 = hb_signal_quality(df_const, ["hb_0", "hb_1"])
    assert q1["signal_quality"] == "constant_or_empty"
    df_ok = pd.DataFrame({"hb_0": [0.0, 2.0], "hb_1": [0.0, 3.0]})
    q2 = hb_signal_quality(df_ok, ["hb_0", "hb_1"])
    assert q2["signal_quality"] in ("weak", "good")
