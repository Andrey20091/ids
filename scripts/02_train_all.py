# =============================================================================
# Скрипт 02: обучение всех моделей кейса 4 — IF (потоки + агрегаты), RF, AE, LSTM,
# классификатор с embedding (порт/протокол + числовой вектор).
# =============================================================================
"""Train RF + IF (+ optional AE/LSTM + embedding if torch installed)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

import numpy as np
import pandas as pd
import shutil
import yaml

from src.features.feature_config import header_byte_columns, load_merged_feature_config
from src.utils.model_health import (
    assess_deep_health,
    git_hash,
    hb_signal_quality,
    json_write,
    load_or_init_baselines,
    settings_hash,
    train_reports_dir,
    ts_token,
    utc_now_iso,
    write_model_status_report,
)
from src.utils.training_policy import (
    baseline_manifest_path,
    build_artifact_manifest_entries,
    get_training_policy,
    is_cicids_tag,
    normalize_dataset_tag,
    write_baseline_manifest,
)


def main() -> None:
    """Загрузка flows.csv, обучение моделей и сохранение артефактов в artifacts/."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data",
        type=str,
        default=str(_ROOT / "data/processed/flows.csv"),
    )
    parser.add_argument(
        "--features-yaml",
        type=str,
        default=str(_ROOT / "config/feature_columns.yaml"),
    )
    parser.add_argument("--skip-torch", action="store_true")
    parser.add_argument(
        "--training-profile",
        type=str,
        default="production",
        help="production | development — см. training_profiles в config/settings.yaml (быстрые эпохи/n_estimators)",
    )
    parser.add_argument("--dataset-tag", type=str, default="")
    parser.add_argument("--dataset-source", type=str, default="")
    parser.add_argument("--baseline-train", action="store_true")
    parser.add_argument("--force-rebaseline", action="store_true")
    args = parser.parse_args()
    with open(_ROOT / "config/settings.yaml", encoding="utf-8") as f:
        settings = yaml.safe_load(f)
    from src.utils.pipeline_validate import apply_training_profile

    settings = apply_training_profile(settings, args.training_profile.strip().lower())
    if args.training_profile.strip().lower() not in ("", "production", "default"):
        print(f"training-profile={args.training_profile}: применены переопределения models.* из settings.yaml")
    feat_cfg = load_merged_feature_config(args.features_yaml)
    policy = get_training_policy(settings)
    dataset_cfg = settings.get("dataset", {}) if isinstance(settings.get("dataset"), dict) else {}
    dataset_tag = normalize_dataset_tag(args.dataset_tag or dataset_cfg.get("tag") or "")
    dataset_source = str(args.dataset_source or dataset_cfg.get("source") or "")
    train_mode = "baseline" if args.baseline_train else "full_retrain"
    policy_decision = "allowed"

    if args.baseline_train and policy.get("enforce_cicids_baseline", False):
        if args.skip_torch and policy.get("disallow_skip_torch_for_baseline", False):
            raise SystemExit(
                "Baseline train blocked by policy: --skip-torch is forbidden for baseline. "
                "Install/fix torch in current interpreter and rerun baseline-train without --skip-torch."
            )
        if not is_cicids_tag(dataset_tag, policy):
            raise SystemExit(
                "Baseline train blocked by policy: dataset-tag must be one of CICIDS tags "
                f"{policy.get('cicids_tag_values', [])}. Got: {dataset_tag or '<empty>'}."
            )
        manifest_path = baseline_manifest_path(settings, _ROOT)
        if manifest_path.exists() and not args.force_rebaseline:
            raise SystemExit(
                f"Baseline manifest already exists: {manifest_path}. "
                "Rebaseline is blocked by default; use --force-rebaseline if policy allows it."
            )
        if args.force_rebaseline and not policy.get("allow_force_rebaseline", False):
            raise SystemExit("Force rebaseline is disabled by policy (training_policy.allow_force_rebaseline=false).")

    if (not args.baseline_train) and policy.get("prohibit_full_retrain_on_new_data", False):
        policy_decision = "blocked:full_retrain_on_new_data"
        raise SystemExit(
            "Full retrain blocked by policy. Use baseline-train for CICIDS2017 or online retrain for new data."
        )
    if_cfg = settings["models"]["isolation_forest"]
    rf_cfg = settings["models"]["random_forest"]
    global_seed = int(rf_cfg.get("random_state", if_cfg.get("random_state", 42)))

    data_path = Path(args.data)
    if not data_path.is_file():
        raise SystemExit(f"Нет файла данных: {data_path.resolve()}. Сначала: python scripts/01_prepare_data.py ...")

    df = pd.read_csv(args.data)
    label_col = feat_cfg.get("label_column", "Label")
    num_cols = [c for c in feat_cfg.get("numeric_features", []) if c in df.columns]
    if not num_cols:
        raise SystemExit(
            "No numeric feature columns found in CSV. Check config/feature_columns.yaml vs file headers."
        )
    X = df[num_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    artifacts = _ROOT / settings["paths"]["artifacts"]
    artifacts.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    train_metrics_for_status: dict[str, dict] = {}
    train_report: dict = {
        "timestamp": utc_now_iso(),
        "dataset_path": str(data_path.resolve()),
        "dataset_rows": int(len(df)),
        "config_path": str((_ROOT / "config/settings.yaml").resolve()),
        "features_yaml_path": str(Path(args.features_yaml).resolve()),
        "config_hash": settings_hash(settings),
        "git_hash": git_hash(_ROOT),
        "training_profile": args.training_profile.strip().lower() or "production",
        "dataset_tag": dataset_tag,
        "dataset_source": dataset_source,
        "train_mode": train_mode,
        "policy_decision": policy_decision,
        "training_policy": policy,
        "random_state": global_seed,
        "models": {
            "rf": {"train_status": "pending", "metrics": {}, "warnings": [], "artifacts": [str(artifacts / "rf_model.joblib"), str(artifacts / "rf_label_encoder.joblib")]},
            "if_flow": {"train_status": "pending", "metrics": {}, "warnings": [], "artifacts": [str(artifacts / "if_model.joblib")]},
            "if_agg": {"train_status": "pending", "metrics": {}, "warnings": [], "artifacts": [str(artifacts / "if_agg_model.joblib"), str(artifacts / "if_model_agg.joblib")]},
            "ae": {"train_status": "pending", "metrics": {}, "warnings": [], "artifacts": [str(artifacts / "ae_model.pt")]},
            "lstm": {"train_status": "pending", "metrics": {}, "warnings": [], "artifacts": [str(artifacts / "lstm_model.pt"), str(artifacts / "lstm_label_encoder.joblib")]},
            "embedding": {
                "train_status": "pending",
                "metrics": {},
                "warnings": [],
                "artifacts": [
                    str(artifacts / "embedding_classifier.pt"),
                    str(artifacts / "embedding_proto_encoder.joblib"),
                    str(artifacts / "embedding_port_encoder.joblib"),
                ],
            },
            "raw_header_cnn": {
                "train_status": "pending",
                "metrics": {},
                "warnings": [],
                "artifacts": [str(artifacts / "raw_header_cnn.pt"), str(artifacts / "raw_header_cnn_label_encoder.joblib")],
            },
        },
    }
    _, baselines = load_or_init_baselines(settings, _ROOT)

    from src.features.aggregate_if_training import make_aggregate_numeric_frame
    from src.models.train_isolation_forest import train_isolation_forest

    # --- Isolation Forest на признаках потока (как раньше) ---
    try:
        if_info = train_isolation_forest(
            X,
            artifacts,
            n_estimators=if_cfg["n_estimators"],
            contamination=if_cfg["contamination"],
            random_state=if_cfg.get("random_state", global_seed),
            artifact_filename="if_model.joblib",
        )
        train_report["models"]["if_flow"]["train_status"] = "ok"
        train_report["models"]["if_flow"]["metrics"] = if_info
        train_metrics_for_status["if_flow"] = if_info
    except Exception as e:
        train_report["models"]["if_flow"]["train_status"] = "error"
        train_report["models"]["if_flow"]["warnings"].append(str(e))
        raise

    # --- Isolation Forest на минутных агрегатах (согласован с L1) ---
    ts_col = feat_cfg.get("timestamp_column")
    agg_freq = settings.get("aggregation", {}).get("resample_freq", "1min")
    if ts_col and ts_col in df.columns:
        agg_num = make_aggregate_numeric_frame(df, ts_col, freq=agg_freq)
        if agg_num is not None and len(agg_num) >= 3:
            agg_info = train_isolation_forest(
                agg_num,
                artifacts,
                n_estimators=if_cfg["n_estimators"],
                contamination=if_cfg["contamination"],
                random_state=if_cfg.get("random_state", global_seed),
                artifact_filename="if_agg_model.joblib",
            )
            # Дублирование имени для обратной совместимости (L1 / старые отчёты).
            shutil.copy2(artifacts / "if_agg_model.joblib", artifacts / "if_model_agg.joblib")
            print("IsolationForest (aggregates):", artifacts / "if_agg_model.joblib")
            train_report["models"]["if_agg"]["train_status"] = "ok"
            train_report["models"]["if_agg"]["metrics"] = {
                **agg_info,
                "aggregate_rows": int(len(agg_num)),
                "aggregate_freq": str(agg_freq),
            }
            train_metrics_for_status["if_agg"] = train_report["models"]["if_agg"]["metrics"]
        else:
            print("Skipping IF aggregates: not enough time buckets.")
            train_report["models"]["if_agg"]["train_status"] = "skipped"
            train_report["models"]["if_agg"]["warnings"].append("not enough aggregate time buckets")
    else:
        print("Skipping IF aggregates: no timestamp column in data.")
        train_report["models"]["if_agg"]["train_status"] = "skipped"
        train_report["models"]["if_agg"]["warnings"].append("timestamp column is missing")

    from src.models.train_random_forest import train_random_forest

    if label_col in df.columns:
        rf_kw = {
            "n_estimators": rf_cfg.get("n_estimators", 200),
            "max_depth": rf_cfg.get("max_depth"),
            "random_state": rf_cfg.get("random_state", global_seed),
        }
        if "is_attack" in df.columns:
            y_rf = df["is_attack"].astype(int).map(lambda x: "ATTACK" if int(x) == 1 else "BENIGN")
        else:
            y_rf = df[label_col].astype(str).map(
                lambda x: "BENIGN" if str(x).strip().upper() == "BENIGN" else "ATTACK"
            )
        try:
            info = train_random_forest(X, y_rf, artifacts, **rf_kw)
        except ValueError as e:
            raise SystemExit(f"RandomForest training skipped: {e}") from e
        print("RandomForest:", info)
        train_report["models"]["rf"]["train_status"] = "ok"
        train_report["models"]["rf"]["metrics"] = info
        train_metrics_for_status["rf"] = info
    else:
        train_report["models"]["rf"]["train_status"] = "skipped"
        train_report["models"]["rf"]["warnings"].append(f"label column '{label_col}' is missing")

    hb_quality = hb_signal_quality(df, header_byte_columns(feat_cfg))
    train_report["hb_signal_quality"] = hb_quality
    if hb_quality.get("warning"):
        warnings.append(str(hb_quality["warning"]))

    if not args.skip_torch:
        try:
            from src.models.train_autoencoder import train_autoencoder
            from src.models.train_embedding_classifier import train_embedding_classifier
            from src.models.train_lstm import train_lstm

            ae_cfg = settings["models"]["autoencoder"]
            normal_mask = df[label_col].astype(str).str.upper().eq("BENIGN") if label_col in df.columns else None
            if normal_mask is not None and normal_mask.any():
                split_idx = max(1, int(len(X) * 0.8))
                normal_train = normal_mask.to_numpy() & (np.arange(len(X)) < split_idx)
                normal_val = normal_mask.to_numpy() & (np.arange(len(X)) >= split_idx)
                ae_info = train_autoencoder(
                    X.loc[normal_train] if normal_train.any() else X.loc[normal_mask],
                    artifacts,
                    encoding_dim=ae_cfg["encoding_dim"],
                    epochs=ae_cfg["epochs"],
                    batch_size=ae_cfg["batch_size"],
                    learning_rate=ae_cfg["learning_rate"],
                    random_state=global_seed,
                    X_val_normal=X.loc[normal_val] if normal_val.any() else None,
                )
                print("Autoencoder:", ae_info)
                train_report["models"]["ae"]["train_status"] = "ok"
                train_report["models"]["ae"]["metrics"] = ae_info
                st, msg, baselines = assess_deep_health("autoencoder", ae_info, baselines)
                train_report["models"]["ae"]["health"] = {"status": st, "message": msg}
                if ae_info.get("val_mse_mean") is None:
                    train_report["models"]["ae"]["warnings"].append(
                        "val_mse_mean is missing; AE health gate is informational for this run"
                    )
                train_metrics_for_status["ae"] = ae_info
            else:
                train_report["models"]["ae"]["train_status"] = "skipped"
                train_report["models"]["ae"]["warnings"].append("no BENIGN rows")
            if label_col in df.columns:
                lstm_cfg = settings["models"]["lstm"]
                seq_len = int(lstm_cfg["sequence_length"])
                if len(X) < seq_len:
                    print("Skipping LSTM: need at least", seq_len, "rows")
                    train_report["models"]["lstm"]["train_status"] = "skipped"
                    train_report["models"]["lstm"]["warnings"].append(f"need at least {seq_len} rows")
                else:
                    try:
                        lstm_info = train_lstm(
                            X,
                            df[label_col],
                            artifacts,
                            sequence_length=seq_len,
                            hidden_size=lstm_cfg["hidden_size"],
                            epochs=lstm_cfg["epochs"],
                            batch_size=lstm_cfg["batch_size"],
                            learning_rate=lstm_cfg["learning_rate"],
                            random_state=global_seed,
                            val_start_row=max(seq_len, int(len(X) * 0.8)),
                        )
                        print("LSTM:", lstm_info)
                        train_report["models"]["lstm"]["train_status"] = "ok"
                        train_report["models"]["lstm"]["metrics"] = lstm_info
                        st, msg, baselines = assess_deep_health("lstm", lstm_info, baselines)
                        train_report["models"]["lstm"]["health"] = {"status": st, "message": msg}
                        train_metrics_for_status["lstm"] = lstm_info
                    except ValueError as e:
                        print("Skipping LSTM:", e)
                        train_report["models"]["lstm"]["train_status"] = "skipped"
                        train_report["models"]["lstm"]["warnings"].append(str(e))

            # --- Embedding-классификатор (Protocol + Destination Port + числовые признаки) ---
            cat = feat_cfg.get("categorical_for_embedding", {})
            proto_col = cat.get("protocol_column", "Protocol")
            port_col = cat.get("port_column", "Destination Port")
            if "is_attack" in df.columns and proto_col in df.columns and port_col in df.columns:
                emb_cfg = settings.get("models", {}).get("embedding", {})
                train_mask = pd.Series(np.arange(len(df)) < max(1, int(len(df) * 0.8)), index=df.index)
                try:
                    emb_info = train_embedding_classifier(
                        df,
                        proto_col=proto_col,
                        port_col=port_col,
                        numeric_cols=num_cols,
                        y_binary=df["is_attack"],
                        artifacts_dir=artifacts,
                        epochs=int(emb_cfg.get("epochs", 15)),
                        batch_size=int(emb_cfg.get("batch_size", 256)),
                        learning_rate=float(emb_cfg.get("learning_rate", 1e-3)),
                        embed_dim=int(emb_cfg.get("embed_dim", 16)),
                        hidden=int(emb_cfg.get("hidden_size", 64)),
                        random_state=int(emb_cfg.get("random_state", global_seed)),
                        train_mask=train_mask,
                    )
                    print("Embedding classifier:", emb_info)
                    train_report["models"]["embedding"]["train_status"] = "ok"
                    train_report["models"]["embedding"]["metrics"] = emb_info
                    st, msg, baselines = assess_deep_health("embedding", emb_info, baselines)
                    train_report["models"]["embedding"]["health"] = {"status": st, "message": msg}
                    oov_port = float(emb_info.get("oov_port_fraction", 0.0) or 0.0)
                    oov_proto = float(emb_info.get("oov_proto_fraction", 0.0) or 0.0)
                    high_oov = bool(max(oov_port, oov_proto) > 0.2)
                    train_report["models"]["embedding"]["stability"] = {
                        "oov_port_fraction": oov_port,
                        "oov_proto_fraction": oov_proto,
                        "high_oov_risk": high_oov,
                    }
                    if high_oov:
                        train_report["models"]["embedding"]["warnings"].append(
                            "high OOV fraction for embedding categories; monitor drift and encoder coverage"
                        )
                    train_metrics_for_status["embedding"] = emb_info
                except Exception as e:
                    print("Embedding classifier skipped:", e)
                    train_report["models"]["embedding"]["train_status"] = "skipped"
                    train_report["models"]["embedding"]["warnings"].append(str(e))
            else:
                train_report["models"]["embedding"]["train_status"] = "skipped"
                train_report["models"]["embedding"]["warnings"].append("is_attack/protocol/port columns are missing")

            # --- CNN по сырым байтам заголовков (hb_*) — ТЗ ---
            hb_cols = header_byte_columns(feat_cfg)
            if label_col in df.columns and hb_cols and all(c in df.columns for c in hb_cols):
                try:
                    from src.models.train_raw_header_cnn import train_raw_header_cnn

                    hb_mat = df[hb_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
                    if float((hb_mat.values ** 2).sum()) > 1e-6:
                        hcfg = settings.get("models", {}).get("raw_header_cnn", {})
                        h_info = train_raw_header_cnn(
                            df,
                            df[label_col],
                            artifacts,
                            hb_columns=hb_cols,
                            epochs=int(hcfg.get("epochs", 25)),
                            batch_size=int(hcfg.get("batch_size", 128)),
                            learning_rate=float(hcfg.get("learning_rate", 0.001)),
                            random_state=global_seed,
                        )
                        print("Raw header CNN:", h_info)
                        train_report["models"]["raw_header_cnn"]["train_status"] = "ok"
                        train_report["models"]["raw_header_cnn"]["metrics"] = h_info
                        train_metrics_for_status["raw_header_cnn"] = h_info
                    else:
                        print("Skipping raw header CNN: hb_* columns are all zero (build NPZ via 16_build_header_byte_dataset.py)")
                        train_report["models"]["raw_header_cnn"]["train_status"] = "skipped"
                        train_report["models"]["raw_header_cnn"]["warnings"].append("hb_* matrix is all zero")
                except Exception as e:
                    print("Raw header CNN skipped:", e)
                    train_report["models"]["raw_header_cnn"]["train_status"] = "skipped"
                    train_report["models"]["raw_header_cnn"]["warnings"].append(str(e))
            else:
                train_report["models"]["raw_header_cnn"]["train_status"] = "skipped"
                train_report["models"]["raw_header_cnn"]["warnings"].append("hb_* or label columns are missing")
        except ImportError as e:
            print("Skipping AE/LSTM/Embedding:", e)
            for name in ("ae", "lstm", "embedding", "raw_header_cnn"):
                train_report["models"][name]["train_status"] = "skipped"
                train_report["models"][name]["warnings"].append(f"torch unavailable: {e}")
    else:
        for name in ("ae", "lstm", "embedding", "raw_header_cnn"):
            train_report["models"][name]["train_status"] = "skipped"
            train_report["models"][name]["warnings"].append("--skip-torch enabled")

    # finalize artifact flags and detect readiness
    for model_name, m in train_report["models"].items():
        art_paths = [Path(p) for p in m.get("artifacts", [])]
        m["artifact_exists"] = all(p.is_file() for p in art_paths)
        m["detect_participation_ready"] = bool(m["artifact_exists"])
        if model_name == "raw_header_cnn" and hb_quality.get("signal_quality") in ("constant_or_empty", "missing"):
            m["detect_participation_ready"] = False
            m["warnings"].append("hb_* signal quality is insufficient for meaningful CNN contribution")
        if model_name == "if_agg" and train_report["models"]["if_agg"]["train_status"] == "skipped":
            m["detect_participation_ready"] = False

    baseline_path, _ = load_or_init_baselines(settings, _ROOT)
    json_write(baseline_path, baselines)
    train_report["warnings"] = warnings
    train_report["baseline_path"] = str(baseline_path)
    rep_dir = train_reports_dir(settings, _ROOT)
    rep_path = rep_dir / f"train_report_{ts_token()}.json"
    json_write(rep_path, train_report)
    print(f"Train report: {rep_path}")
    write_model_status_report(settings, last_train_metrics=train_metrics_for_status, base=_ROOT)

    if args.baseline_train:
        manifest = {
            "timestamp": utc_now_iso(),
            "dataset_tag": dataset_tag,
            "dataset_source": dataset_source,
            "dataset_path": str(data_path.resolve()),
            "train_report_path": str(rep_path),
            "training_profile": args.training_profile.strip().lower() or "production",
            "config_hash": train_report.get("config_hash"),
            "git_hash": train_report.get("git_hash"),
            "artifacts": build_artifact_manifest_entries([Path(p) for m in train_report["models"].values() for p in m.get("artifacts", [])]),
        }
        man_path = baseline_manifest_path(settings, _ROOT)
        write_baseline_manifest(man_path, manifest)
        print(f"Baseline manifest: {man_path}")

    print("Artifacts in", artifacts)


if __name__ == "__main__":
    main()
