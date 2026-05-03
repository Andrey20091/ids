import os
import subprocess
import sys
from pathlib import Path

import pandas as pd
import yaml


def _write_settings(path: Path) -> None:
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
        "training_policy": {
            "enforce_cicids_baseline": True,
            "require_baseline_before_online": True,
            "prohibit_full_retrain_on_new_data": True,
            "cicids_tag_values": ["cicids2017"],
            "baseline_manifest_path": "storage/baseline_manifest.json",
            "allow_force_rebaseline": False,
        },
        "models": {
            "random_forest": {"n_estimators": 10, "max_depth": 6, "random_state": 42},
            "isolation_forest": {"n_estimators": 10, "contamination": 0.1, "random_state": 42},
            "autoencoder": {"encoding_dim": 8, "epochs": 1, "batch_size": 16, "learning_rate": 0.001},
            "lstm": {"hidden_size": 8, "sequence_length": 3, "epochs": 1, "batch_size": 8, "learning_rate": 0.001},
            "embedding": {"epochs": 1, "hidden_size": 8, "embed_dim": 4, "batch_size": 8, "learning_rate": 0.001, "random_state": 42},
            "raw_header_cnn": {"epochs": 1, "batch_size": 8, "learning_rate": 0.001},
        },
    }
    path.write_text(yaml.safe_dump(settings, sort_keys=False, allow_unicode=False), encoding="utf-8")


def _write_features(path: Path) -> None:
    feat = {
        "header_raw_bytes": {"enabled": True, "max_packets": 1, "bytes_per_packet": 4, "column_prefix": "hb_"},
        "numeric_features": ["f1", "f2", "SYN Flag Count"],
        "categorical_for_embedding": {"protocol_column": "Protocol", "port_column": "Destination Port"},
        "label_column": "Label",
        "timestamp_column": "Timestamp",
    }
    path.write_text(yaml.safe_dump(feat, sort_keys=False, allow_unicode=False), encoding="utf-8")


def test_train_blocked_when_policy_prohibits_full_retrain(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    _write_settings(tmp_path / "config" / "settings.yaml")
    _write_features(tmp_path / "config" / "feature_columns.yaml")

    df = pd.DataFrame(
        {
            "f1": [1.0, 2.0, 3.0, 4.0],
            "f2": [4.0, 3.0, 2.0, 1.0],
            "SYN Flag Count": [0.0, 1.0, 0.0, 1.0],
            "Protocol": [6, 17, 6, 17],
            "Destination Port": [80, 443, 80, 443],
            "Timestamp": pd.date_range("2026-01-01", periods=4, freq="min").astype(str),
            "Label": ["BENIGN", "Attack", "BENIGN", "Attack"],
            "is_attack": [0, 1, 0, 1],
            "hb_0": [0.0] * 4,
            "hb_1": [0.0] * 4,
            "hb_2": [0.0] * 4,
            "hb_3": [0.0] * 4,
        }
    )
    data_path = tmp_path / "data" / "processed" / "flows.csv"
    data_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(data_path, index=False)

    env = dict(os.environ)
    env["IDS_PROJECT_ROOT"] = str(tmp_path)
    proc = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "02_train_all.py"),
            "--data",
            str(data_path),
            "--skip-torch",
            "--dataset-tag",
            "custom",
        ],
        cwd=root,
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode != 0
    assert "Full retrain blocked by policy" in (proc.stdout + proc.stderr)
