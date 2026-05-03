# =============================================================================
# Периодическое дообучение Isolation Forest с валидационным «шлюзом» (кейс 4).
# =============================================================================
"""Periodic retrain every N minutes (ТЗ: 15 min)."""

from __future__ import annotations

import json
import shutil
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.preprocessing import LabelEncoder

from src.features.aggregate_if_training import (
    agg_if_alignment_f1,
    aggregate_bucket_attack_labels,
    make_aggregate_numeric_frame,
    make_aggregate_numeric_with_timestamps,
)
from src.features.feature_config import load_merged_feature_config
from src.models.train_isolation_forest import train_isolation_forest
from src.online.validation_gate import simple_validation_f1
from src.governance.storage import append_jsonl, utc_now_iso
from src.online.buffer_integrity import (
    fingerprint_data_row,
    fingerprint_first_data_row,
    fingerprint_prefix_last_row,
    prefix_interior_checksum,
)
from src.utils.buffer_csv import read_flows_buffer_csv
from src.online.buffer_rotation import read_rotation_generation
from src.utils_config import load_settings, project_root, resolve_from_project_root
from src.utils.model_health import assess_deep_health, json_write, load_or_init_baselines, write_model_status_report
from src.utils.training_policy import baseline_manifest_path, get_training_policy, read_baseline_manifest

_DEEP_ARTIFACTS = (
    "ae_model.pt",
    "lstm_model.pt",
    "lstm_label_encoder.joblib",
    "embedding_classifier.pt",
    "embedding_proto_encoder.joblib",
    "embedding_port_encoder.joblib",
    "raw_header_cnn.pt",
    "raw_header_cnn_label_encoder.joblib",
)


def _watermark_paths(settings: dict, root: Path, processed_csv: str | Path) -> tuple[bool, Path | None]:
    on = settings.get("online", {}) or {}
    wm_cfg = on.get("watermark", {}) or {}
    enabled = bool(wm_cfg.get("enabled", True))
    if not enabled:
        return False, None
    paths = settings.get("paths", {}) or {}
    online_buf = resolve_from_project_root(paths.get("flows_online_buffer", "data/processed/flows_online_buffer.csv")).resolve()
    current_csv = resolve_from_project_root(processed_csv).resolve()
    if current_csv != online_buf:
        return False, None
    st_rel = str(wm_cfg.get("state_path", "storage/online_buffer_watermark.json")).strip()
    st = resolve_from_project_root(st_rel if st_rel else "storage/online_buffer_watermark.json")
    if not st.is_absolute():
        st = root / st
    return True, st


def _read_watermark_state(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _write_watermark_rows(
    path: Path,
    rows_processed: int,
    source_csv: str | Path,
    *,
    buffer_path: Path,
    rotation_generation: int,
    file_size_bytes: int | None = None,
    head_data_fingerprint: str | None = None,
    prefix_last_row_fingerprint: str | None = None,
    prefix_interior_checksum: str | None = None,
) -> None:
    """
    Watermark привязан к rotation_generation из .<stem>.meta.json рядом с буфером.
    При смене поколения (ротация prepare / maintain) meta инкрементируется — если запись
    в JSON отстаёт, обработчик сбрасывает rows_processed (см. run_one_retrain_iteration).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "buffer_path": str(buffer_path.resolve()),
        "rotation_generation": int(max(0, rotation_generation)),
        "rows_processed": int(max(0, rows_processed)),
        "source_csv": str(source_csv),
        "updated_at": utc_now_iso(),
    }
    if file_size_bytes is not None:
        payload["file_size_bytes"] = int(max(0, file_size_bytes))
    if head_data_fingerprint:
        payload["head_data_fingerprint"] = str(head_data_fingerprint)
    if prefix_last_row_fingerprint:
        payload["prefix_last_row_fingerprint"] = str(prefix_last_row_fingerprint)
    if prefix_interior_checksum:
        payload["prefix_interior_checksum"] = str(prefix_interior_checksum)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _backup_deep_artifacts(artifacts_dir: Path) -> None:
    for name in _DEEP_ARTIFACTS:
        p = artifacts_dir / name
        if p.is_file():
            shutil.copy2(p, artifacts_dir / f"{name}.bak")


def _retrain_if_aggregate(
    df: pd.DataFrame,
    split: int,
    artifacts_dir: Path,
    settings: dict,
    feat_cfg: dict,
) -> dict:
    """
    Переобучить ``if_agg_model.joblib`` (копия ``if_model_agg.joblib``) на агрегатах ``aggregate_flows_by_time``.

    Val-gate (отдельно от потокового IF): proxy-F1(IF outlier vs ``max(is_attack)`` по минутному бакету на val).
    """
    from sklearn.ensemble import IsolationForest

    ts_col = feat_cfg.get("timestamp_column")
    agg_freq = settings.get("aggregation", {}).get("resample_freq", "1min")
    gate_cfg = settings.get("online", {}).get("agg_if_validation", {}) or {}
    gate_on = bool(gate_cfg.get("enabled", True))
    min_delta = float(gate_cfg.get("min_f1_vs_baseline", -0.05))

    if not ts_col or ts_col not in df.columns:
        return {"status": "skipped", "reason": "no timestamp column"}
    df_train = df.iloc[:split]
    agg_train = make_aggregate_numeric_frame(df_train, ts_col, freq=agg_freq)
    if agg_train is None or len(agg_train) < 3:
        return {"status": "skipped", "reason": "insufficient aggregate buckets"}

    cfg = settings["models"]["isolation_forest"]
    model_new = IsolationForest(
        n_estimators=int(cfg["n_estimators"]),
        contamination=float(cfg["contamination"]),
        random_state=int(cfg.get("random_state", 42)),
        n_jobs=-1,
    )
    model_new.fit(agg_train)

    val_report: dict[str, float] = {}
    df_val = df.iloc[split:]
    if gate_on and len(df_val) >= 2 and "is_attack" in df_val.columns:
        ts_num = make_aggregate_numeric_with_timestamps(df_val, ts_col, freq=agg_freq)
        if ts_num is not None:
            bucket_ts, num_val = ts_num
            ba = aggregate_bucket_attack_labels(df_val, ts_col, "is_attack", agg_freq)
            val_report = agg_if_alignment_f1(bucket_ts, num_val, model_new, ba)
            f1_new = float(val_report.get("f1", 0.0))
            baseline_path = artifacts_dir / "if_agg_validation_baseline.json"
            baseline_f1 = None
            if baseline_path.is_file():
                baseline_f1 = json.loads(baseline_path.read_text(encoding="utf-8")).get("f1")
            worse = False
            if baseline_f1 is not None:
                worse = f1_new < baseline_f1 + min_delta
            if worse:
                return {
                    "status": "rejected",
                    "reason": "agg IF proxy F1 not improved vs baseline",
                    "agg_if_val_f1": f1_new,
                    "agg_if_baseline_f1": baseline_f1,
                }
            baseline_path.write_text(json.dumps({"f1": f1_new}, indent=2), encoding="utf-8")

    agg_primary = artifacts_dir / "if_agg_model.joblib"
    agg_legacy = artifacts_dir / "if_model_agg.joblib"
    for ap in (agg_primary, agg_legacy):
        bak = artifacts_dir / f"{ap.name}.bak"
        if ap.is_file():
            shutil.copy2(ap, bak)
    try:
        joblib.dump(model_new, agg_primary)
        shutil.copy2(agg_primary, agg_legacy)
        out = {"status": "ok", "n_agg_rows": len(agg_train), **{k: val_report[k] for k in val_report}}
        return out
    except Exception as e:
        for ap in (agg_primary, agg_legacy):
            bak = artifacts_dir / f"{ap.name}.bak"
            if bak.is_file():
                shutil.copy2(bak, ap)
        return {"status": "error", "reason": str(e)}


def _restore_one(artifacts_dir: Path, name: str) -> None:
    bak = artifacts_dir / f"{name}.bak"
    if bak.is_file():
        shutil.copy2(bak, artifacts_dir / name)


def _retrain_deep_models(
    df: pd.DataFrame,
    X: pd.DataFrame,
    artifacts_dir: Path,
    settings: dict,
    split: int,
    feat_cfg: dict,
) -> dict:
    """
    Дообучить AE/LSTM/Embedding; при deep_validation — откат при ухудшении val-метрик (ТЗ).
    """
    report: dict[str, str] = {
        "raw_header_cnn": "offline_only: retrain via scripts/02_train_all.py (hb_* required)",
    }
    deep_metrics: dict[str, dict] = {}
    deep_health: dict[str, dict] = {}
    baseline_path, baselines = load_or_init_baselines(settings, project_root())
    if not settings["online"].get("retrain_deep_models", True):
        return {
            "status": "skipped",
            "reason": "retrain_deep_models disabled",
            "raw_header_cnn": report["raw_header_cnn"],
            "metrics": deep_metrics,
            "health": deep_health,
        }

    num_cols = [c for c in feat_cfg.get("numeric_features", []) if c in df.columns]
    if not num_cols:
        return {
            "status": "skipped",
            "reason": "no numeric columns for deep retrain",
            "raw_header_cnn": report["raw_header_cnn"],
            "metrics": deep_metrics,
            "health": deep_health,
        }
    epochs_cfg = settings["online"].get("deep_models_epochs", {})
    label_col = feat_cfg.get("label_column", "Label")
    dv = settings["online"].get("deep_validation", {}) or {}
    use_gate = bool(dv.get("enabled", True))
    n = len(df)
    train_pos = np.arange(n) < split
    train_mask = pd.Series(train_pos, index=df.index)

    try:
        from src.models.train_autoencoder import train_autoencoder
        from src.models.train_embedding_classifier import train_embedding_classifier
        from src.models.train_lstm import train_lstm
    except ImportError as e:
        return {
            "status": "skipped",
            "reason": f"torch models unavailable: {e}",
            "raw_header_cnn": report["raw_header_cnn"],
            "metrics": deep_metrics,
            "health": deep_health,
        }

    _backup_deep_artifacts(artifacts_dir)
    ae_ratio = float(dv.get("ae_max_val_mse_ratio", 1.12))
    lstm_d = float(dv.get("lstm_min_val_f1_vs_baseline", -0.02))
    emb_d = float(dv.get("embedding_min_val_acc_vs_baseline", -0.02))

    # --- Autoencoder (нормальный train / val по строкам CSV) ---
    if label_col in df.columns:
        normal_mask = df[label_col].astype(str).str.upper().eq("BENIGN").to_numpy()
        nt = normal_mask & train_pos
        nv = normal_mask & ~train_pos
        if nt.any():
            try:
                if use_gate and nv.any():
                    ae_info = train_autoencoder(
                        X.loc[nt],
                        artifacts_dir,
                        encoding_dim=32,
                        epochs=int(epochs_cfg.get("autoencoder", 5)),
                        batch_size=256,
                        learning_rate=1e-3,
                        X_val_normal=X.loc[nv],
                    )
                    new_mse = ae_info.get("val_mse_mean")
                    bp = artifacts_dir / "ae_val_mse_baseline.json"
                    ok = True
                    if new_mse is not None and bp.is_file():
                        old = json.loads(bp.read_text(encoding="utf-8")).get("mse")
                        if old is not None and float(new_mse) > float(old) * ae_ratio:
                            ok = False
                    if ok:
                        if new_mse is not None:
                            bp.write_text(json.dumps({"mse": float(new_mse)}), encoding="utf-8")
                            deep_metrics["autoencoder"] = {"val_mse_mean": float(new_mse)}
                            hs, msg, baselines = assess_deep_health("autoencoder", deep_metrics["autoencoder"], baselines)
                            deep_health["autoencoder"] = {"status": hs, "message": msg}
                        report["autoencoder"] = f"ok:{ae_info.get('model_path', '')}"
                    else:
                        _restore_one(artifacts_dir, "ae_model.pt")
                        report["autoencoder"] = "rejected:val mse worse than baseline"
                        deep_health["autoencoder"] = {"status": "degraded", "message": "val mse worse than baseline gate"}
                else:
                    ae_info = train_autoencoder(
                        X.loc[normal_mask],
                        artifacts_dir,
                        encoding_dim=32,
                        epochs=int(epochs_cfg.get("autoencoder", 5)),
                        batch_size=256,
                        learning_rate=1e-3,
                    )
                    report["autoencoder"] = f"ok:{ae_info.get('model_path', '')}"
                    if ae_info.get("val_mse_mean") is not None:
                        deep_metrics["autoencoder"] = {"val_mse_mean": float(ae_info["val_mse_mean"])}
                        hs, msg, baselines = assess_deep_health("autoencoder", deep_metrics["autoencoder"], baselines)
                        deep_health["autoencoder"] = {"status": hs, "message": msg}
            except Exception as e:
                report["autoencoder"] = f"error:{e}"
                _restore_one(artifacts_dir, "ae_model.pt")
                deep_health["autoencoder"] = {"status": "warning", "message": str(e)}
        else:
            report["autoencoder"] = "skipped:no benign rows"
            deep_health["autoencoder"] = {"status": "warning", "message": "no benign rows for AE retrain"}
    else:
        report["autoencoder"] = "skipped:no label column"
        deep_health["autoencoder"] = {"status": "warning", "message": "label column is missing"}

    # --- LSTM ---
    seq_len = int(settings.get("models", {}).get("lstm", {}).get("sequence_length", 20))
    if label_col in df.columns and len(X) >= seq_len + 1 and split > seq_len:
        try:
            lstm_cfg = settings["models"]["lstm"]
            if use_gate:
                lstm_info = train_lstm(
                    X,
                    df[label_col],
                    artifacts_dir,
                    sequence_length=seq_len,
                    hidden_size=lstm_cfg["hidden_size"],
                    epochs=int(epochs_cfg.get("lstm", 3)),
                    batch_size=lstm_cfg.get("batch_size", 128),
                    learning_rate=lstm_cfg["learning_rate"],
                    val_start_row=split,
                )
                vf = lstm_info.get("val_f1")
                bp = artifacts_dir / "lstm_val_f1_baseline.json"
                ok = True
                if vf is not None and bp.is_file():
                    old = json.loads(bp.read_text(encoding="utf-8")).get("f1")
                    if old is not None and float(vf) < float(old) + lstm_d:
                        ok = False
                if ok:
                    if vf is not None:
                        bp.write_text(json.dumps({"f1": float(vf)}), encoding="utf-8")
                        deep_metrics["lstm"] = {"val_f1": float(vf)}
                        hs, msg, baselines = assess_deep_health("lstm", deep_metrics["lstm"], baselines)
                        deep_health["lstm"] = {"status": hs, "message": msg}
                    report["lstm"] = f"ok:{lstm_info.get('model_path', '')}"
                else:
                    _restore_one(artifacts_dir, "lstm_model.pt")
                    _restore_one(artifacts_dir, "lstm_label_encoder.joblib")
                    report["lstm"] = "rejected:val F1 worse than baseline"
                    deep_health["lstm"] = {"status": "degraded", "message": "val F1 worse than baseline gate"}
            else:
                lstm_info = train_lstm(
                    X,
                    df[label_col],
                    artifacts_dir,
                    sequence_length=seq_len,
                    hidden_size=lstm_cfg["hidden_size"],
                    epochs=int(epochs_cfg.get("lstm", 3)),
                    batch_size=lstm_cfg.get("batch_size", 128),
                    learning_rate=lstm_cfg["learning_rate"],
                )
                report["lstm"] = f"ok:{lstm_info.get('model_path', '')}"
                if lstm_info.get("val_f1") is not None:
                    deep_metrics["lstm"] = {"val_f1": float(lstm_info["val_f1"])}
                    hs, msg, baselines = assess_deep_health("lstm", deep_metrics["lstm"], baselines)
                    deep_health["lstm"] = {"status": hs, "message": msg}
        except ValueError as e:
            report["lstm"] = f"skipped:{e}"
            deep_health["lstm"] = {"status": "warning", "message": str(e)}
        except Exception as e:
            report["lstm"] = f"error:{e}"
            _restore_one(artifacts_dir, "lstm_model.pt")
            _restore_one(artifacts_dir, "lstm_label_encoder.joblib")
            deep_health["lstm"] = {"status": "warning", "message": str(e)}
    else:
        report["lstm"] = "skipped:no label or not enough rows / split too small"
        deep_health["lstm"] = {"status": "warning", "message": "not enough rows or labels for LSTM retrain"}

    proto_col = feat_cfg.get("categorical_for_embedding", {}).get("protocol_column", "Protocol")
    port_col = feat_cfg.get("categorical_for_embedding", {}).get("port_column", "Destination Port")
    if proto_col in df.columns and port_col in df.columns and "is_attack" in df.columns:
        try:
            if use_gate and split > 0 and split < n:
                emb_info = train_embedding_classifier(
                    df=df,
                    proto_col=proto_col,
                    port_col=port_col,
                    numeric_cols=num_cols,
                    y_binary=df["is_attack"].astype(int),
                    artifacts_dir=artifacts_dir,
                    epochs=int(epochs_cfg.get("embedding", 3)),
                    train_mask=train_mask,
                )
                va = emb_info.get("val_acc")
                bp = artifacts_dir / "embedding_val_acc_baseline.json"
                ok = True
                if va is not None and bp.is_file():
                    old = json.loads(bp.read_text(encoding="utf-8")).get("acc")
                    if old is not None and float(va) < float(old) + emb_d:
                        ok = False
                if ok:
                    if va is not None:
                        bp.write_text(json.dumps({"acc": float(va)}), encoding="utf-8")
                        deep_metrics["embedding"] = {"val_acc": float(va)}
                        hs, msg, baselines = assess_deep_health("embedding", deep_metrics["embedding"], baselines)
                        deep_health["embedding"] = {"status": hs, "message": msg}
                    report["embedding"] = f"ok:{emb_info.get('path', '')}"
                else:
                    _restore_one(artifacts_dir, "embedding_classifier.pt")
                    _restore_one(artifacts_dir, "embedding_proto_encoder.joblib")
                    _restore_one(artifacts_dir, "embedding_port_encoder.joblib")
                    report["embedding"] = "rejected:val acc worse than baseline"
                    deep_health["embedding"] = {"status": "degraded", "message": "val acc worse than baseline gate"}
            else:
                emb_info = train_embedding_classifier(
                    df=df,
                    proto_col=proto_col,
                    port_col=port_col,
                    numeric_cols=num_cols,
                    y_binary=df["is_attack"].astype(int),
                    artifacts_dir=artifacts_dir,
                    epochs=int(epochs_cfg.get("embedding", 3)),
                )
                report["embedding"] = f"ok:{emb_info.get('path', '')}"
                if emb_info.get("val_acc") is not None:
                    deep_metrics["embedding"] = {"val_acc": float(emb_info["val_acc"])}
                    hs, msg, baselines = assess_deep_health("embedding", deep_metrics["embedding"], baselines)
                    deep_health["embedding"] = {"status": hs, "message": msg}
        except Exception as e:
            report["embedding"] = f"skipped:{e}"
            _restore_one(artifacts_dir, "embedding_classifier.pt")
            _restore_one(artifacts_dir, "embedding_proto_encoder.joblib")
            _restore_one(artifacts_dir, "embedding_port_encoder.joblib")
            deep_health["embedding"] = {"status": "warning", "message": str(e)}
    else:
        report["embedding"] = "skipped:missing cols/probably no is_attack"
        deep_health["embedding"] = {"status": "warning", "message": "missing columns for embedding retrain"}

    json_write(baseline_path, baselines)
    report["metrics"] = deep_metrics
    report["health"] = deep_health
    return report


def run_one_retrain_iteration(
    processed_csv: str | Path,
    artifacts_dir: str | Path | None = None,
) -> dict:
    """
    Одна итерация: переобучить IF на числовых признаках; откат при ухудшении F1 на val.

    Требуется колонка ``is_attack`` в CSV и достаточное число строк (см. settings).
    """
    settings = load_settings()
    root = project_root()
    policy = get_training_policy(settings)
    run_id = f"rt_{utc_now_iso().replace(':', '').replace('-', '').replace('T', '_').replace('Z', '')}"
    artifacts_dir = Path(artifacts_dir) if artifacts_dir is not None else resolve_from_project_root(settings["paths"]["artifacts"])
    if not artifacts_dir.is_absolute():
        artifacts_dir = root / artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    storage_rel = Path(settings["paths"].get("storage", "storage"))
    history_path = (storage_rel if storage_rel.is_absolute() else (root / storage_rel)) / "retrain_history.jsonl"

    def _record(result: dict, n_rows: int = 0) -> dict:
        st = result.get("status", "unknown")
        on = settings.get("online", {}) or {}
        dv = on.get("deep_validation") or {}
        payload = {
            "run_id": run_id,
            "ts": utc_now_iso(),
            "result": st,
            "reason": result.get("reason", ""),
            "input_rows": int(n_rows),
            "if_metrics": result.get("metrics", {}),
            "if_baseline_f1": result.get("baseline_f1"),
            "rf_f1": result.get("rf_f1"),
            "rf_baseline_f1": result.get("rf_baseline_f1"),
            "deep_models": result.get("deep_models", {}),
            "if_aggregate": result.get("if_aggregate", {}),
            "retrain_interval_minutes": int(on.get("retrain_interval_minutes", 15)),
            "min_samples_retrain_threshold": int(on.get("min_samples_retrain", 5000)),
            "deep_validation_enabled": bool(dv.get("enabled", True)),
            "iteration_semantics": (
                "Одна строка JSONL = один вызов run_one_retrain_iteration (тик планировщика или ручной запуск). "
                "Интервал online.retrain_interval_minutes задаёт частоту попыток, а не гарантию обновления весов. "
                "result=ok — IF прошёл валидацию и записан; RF/глубокие модели — см. поля выше. "
                "result=skipped — дообучение не запускалось (например input_rows < min_samples_retrain_threshold). "
                "result=rejected — откат IF; в deep_models возможны отдельные rejected после val gate."
            ),
        }
        append_jsonl(history_path, payload)
        return result

    if policy.get("require_baseline_before_online", False):
        man_path = baseline_manifest_path(settings, root)
        man, err = read_baseline_manifest(man_path)
        if man is None:
            res = _record({"status": "skipped", "reason": f"baseline policy gate: {err}"}, n_rows=0)
            try:
                write_model_status_report(settings, base=root)
            except Exception as e:
                warnings.warn(
                    f"Failed to refresh model_status_report after baseline gate skip: {e}",
                    UserWarning,
                    stacklevel=2,
                )
            return res

    try:
        df = read_flows_buffer_csv(processed_csv, low_memory=False)
        df_full = df
        head_fp_open = fingerprint_first_data_row(df)
    except ValueError as e:
        res = _record({"status": "skipped", "reason": str(e)}, n_rows=0)
        try:
            write_model_status_report(settings, base=root)
        except Exception as ie:
            warnings.warn(
                f"Failed to refresh model_status_report after buffer encoding skip: {ie}",
                UserWarning,
                stacklevel=2,
            )
        return res
    except Exception as e:
        res = _record({"status": "skipped", "reason": f"failed to read processed csv: {e}"}, n_rows=0)
        try:
            write_model_status_report(settings, base=root)
        except Exception as ie:
            warnings.warn(
                f"Failed to refresh model_status_report after CSV read skip: {ie}",
                UserWarning,
                stacklevel=2,
            )
        return res
    wm_enabled, wm_path = _watermark_paths(settings, root, processed_csv)
    wm_prev_rows = 0
    wm_next_rows = 0
    buffer_resolved = Path(processed_csv).resolve()
    if wm_enabled and wm_path is not None:
        current_gen = read_rotation_generation(buffer_resolved)
        wm_payload = _read_watermark_state(wm_path)
        raw_wm_gen = wm_payload.get("rotation_generation")
        if raw_wm_gen is None:
            # Legacy-файл без поля: эквивалентно текущему meta; усечение по числу строк — ниже.
            wm_gen = current_gen
        else:
            try:
                wm_gen = int(raw_wm_gen)
            except (TypeError, ValueError):
                wm_gen = current_gen
        if int(wm_gen) != int(current_gen):
            # Буфер заменён или прошла ротация (prepare / online_buffer_maintain): сброс anchor.
            wm_prev_rows = 0
        else:
            wm_prev_rows = max(0, int(wm_payload.get("rows_processed", 0) or 0))
            stored_head = wm_payload.get("head_data_fingerprint")
            if stored_head and head_fp_open:
                # То же поколение, но первая строка данных не совпадает — правка файла без ротации.
                if str(stored_head) != str(head_fp_open):
                    wm_prev_rows = 0
        total_rows = int(len(df))
        if total_rows < wm_prev_rows:
            wm_prev_rows = 0
        stored_prefix = wm_payload.get("prefix_last_row_fingerprint")
        if wm_prev_rows > 0 and stored_prefix and total_rows >= wm_prev_rows:
            # Граница обработанного префикса (последняя «закрытая» строка) изменилась — сброс anchor.
            cur_pref = fingerprint_data_row(df.iloc[wm_prev_rows - 1])
            if str(stored_prefix) != str(cur_pref):
                wm_prev_rows = 0
        stored_int = wm_payload.get("prefix_interior_checksum")
        if wm_prev_rows > 0 and stored_int and wm_prev_rows >= 3:
            cur_int = prefix_interior_checksum(df, wm_prev_rows)
            if cur_int and str(stored_int) != str(cur_int):
                # Правка внутри префикса (между первой и граничной строкой) — сброс anchor.
                wm_prev_rows = 0
        if total_rows <= wm_prev_rows:
            res = _record({"status": "skipped", "reason": "no new rows since watermark"}, n_rows=0)
            try:
                write_model_status_report(settings, base=root)
            except Exception as e:
                warnings.warn(
                    f"Failed to refresh model_status_report after watermark skip: {e}",
                    UserWarning,
                    stacklevel=2,
                )
            return res
        df = df.iloc[wm_prev_rows:].reset_index(drop=True)
        wm_next_rows = total_rows
    feat_path = root / "config" / "feature_columns.yaml"
    try:
        feat_cfg = load_merged_feature_config(feat_path)
    except FileNotFoundError:
        warnings.warn(
            f"Feature config not found at {feat_path}; falling back to numeric-dtype columns.",
            UserWarning,
            stacklevel=2,
        )
        feat_cfg = {"numeric_features": [], "timestamp_column": None}
    num_cols = [c for c in feat_cfg.get("numeric_features", []) if c in df.columns]
    if not num_cols:
        num = df.select_dtypes(include=["number"]).fillna(0)
    else:
        num = df[num_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    if "is_attack" not in df.columns:
        res = _record({"status": "skipped", "reason": "need is_attack column for validation_gate"}, n_rows=len(num))
        try:
            write_model_status_report(settings, base=root)
        except Exception as e:
            warnings.warn(
                f"Failed to refresh model_status_report after online skip: {e}",
                UserWarning,
                stacklevel=2,
            )
        return res

    n = len(num)
    min_samples = settings["online"]["min_samples_retrain"]
    if n < min_samples:
        res = _record({"status": "skipped", "reason": f"need >= {min_samples} rows"}, n_rows=n)
        try:
            write_model_status_report(settings, base=root)
        except Exception as e:
            warnings.warn(
                f"Failed to refresh model_status_report after online skip: {e}",
                UserWarning,
                stacklevel=2,
            )
        return res

    val_ratio = settings["online"]["validation_size_ratio"]
    split = int(n * (1 - val_ratio))
    if split <= 0 or split >= n:
        res = _record(
            {
                "status": "skipped",
                "reason": f"invalid train/val split (n={n}, validation_size_ratio={val_ratio})",
            },
            n_rows=n,
        )
        try:
            write_model_status_report(settings, base=root)
        except Exception as e:
            warnings.warn(
                f"Failed to refresh model_status_report after invalid split skip: {e}",
                UserWarning,
                stacklevel=2,
            )
        return res
    X_train, X_val = num.iloc[:split], num.iloc[split:]
    y_val = df["is_attack"].iloc[split:]

    baseline_path = artifacts_dir / "if_validation_baseline.json"
    baseline_f1 = None
    if baseline_path.is_file():
        baseline_f1 = json.loads(baseline_path.read_text(encoding="utf-8")).get("f1")

    model_path = artifacts_dir / "if_model.joblib"
    old_model = joblib.load(model_path) if model_path.is_file() else None

    cfg = settings["models"]["isolation_forest"]
    try:
        train_isolation_forest(
            X_train,
            artifacts_dir,
            n_estimators=cfg["n_estimators"],
            contamination=cfg["contamination"],
        )
    except Exception as e:
        res = _record(
            {
                "status": "error",
                "reason": f"if retrain failed: {e}",
            },
            n_rows=n,
        )
        try:
            write_model_status_report(settings, base=root)
        except Exception as ie:
            warnings.warn(
                f"Failed to refresh model_status_report after IF error: {ie}",
                UserWarning,
                stacklevel=2,
            )
        return res

    from sklearn.ensemble import IsolationForest

    model: IsolationForest = joblib.load(model_path)
    pred = model.predict(X_val)
    pred_binary = (pred == -1).astype(int)
    metrics = simple_validation_f1(y_val.astype(int), pred_binary)
    new_f1 = metrics["f1"]

    accept_equal = settings["online"].get("if_accept_equal_f1", True)
    worse = False
    if baseline_f1 is not None:
        worse = new_f1 < baseline_f1 if accept_equal else new_f1 <= baseline_f1

    if worse:
        if old_model is not None:
            joblib.dump(old_model, model_path)
        res = _record({
            "status": "rejected",
            "metrics": metrics,
            "baseline_f1": baseline_f1,
            "reason": "validation F1 not improved vs baseline",
        }, n_rows=n)
        if wm_enabled and wm_path is not None:
            _sz = buffer_resolved.stat().st_size if buffer_resolved.is_file() else None
            _write_watermark_rows(
                wm_path,
                wm_next_rows,
                processed_csv,
                buffer_path=buffer_resolved,
                rotation_generation=read_rotation_generation(buffer_resolved),
                file_size_bytes=_sz,
                head_data_fingerprint=head_fp_open,
                prefix_last_row_fingerprint=fingerprint_prefix_last_row(df_full, wm_next_rows),
                prefix_interior_checksum=prefix_interior_checksum(df_full, wm_next_rows),
            )
        try:
            write_model_status_report(settings, base=root)
        except Exception as e:
            warnings.warn(
                f"Failed to refresh model_status_report after IF reject: {e}",
                UserWarning,
                stacklevel=2,
            )
        return res

    if_agg_report = _retrain_if_aggregate(df, split, artifacts_dir, settings, feat_cfg)

    # RF refresh (binary BENIGN/ATTACK contract) with guard against regressions.
    rf_cfg = settings["models"]["random_forest"]
    rf_path = artifacts_dir / "rf_model.joblib"
    rf_le_path = artifacts_dir / "rf_label_encoder.joblib"
    rf_baseline_path = artifacts_dir / "rf_validation_baseline.json"
    rf_old_model = joblib.load(rf_path) if rf_path.is_file() else None
    rf_old_le = joblib.load(rf_le_path) if rf_le_path.is_file() else None
    rf_baseline_f1 = None
    if rf_baseline_path.is_file():
        rf_baseline_f1 = json.loads(rf_baseline_path.read_text(encoding="utf-8")).get("f1")

    y_train = df["is_attack"].iloc[:split].astype(int)
    y_val_int = y_val.astype(int)
    y_train_lbl = y_train.map(lambda x: "ATTACK" if int(x) == 1 else "BENIGN")
    le_rf = LabelEncoder()
    y_train_enc = le_rf.fit_transform(y_train_lbl.astype(str))
    rf_f1 = None
    rf_error = None
    try:
        rf = RandomForestClassifier(
            n_estimators=int(rf_cfg.get("n_estimators", 200)),
            max_depth=rf_cfg.get("max_depth"),
            random_state=int(rf_cfg.get("random_state", 42)),
            n_jobs=-1,
        )
        rf.fit(X_train, y_train_enc)
        rf_pred_enc = rf.predict(X_val)
        rf_pred_lbl = le_rf.inverse_transform(rf_pred_enc)
        rf_pred = np.where(pd.Series(rf_pred_lbl).astype(str).str.upper().eq("ATTACK"), 1, 0)
        rf_f1 = float(f1_score(y_val_int, rf_pred, zero_division=0))
    except Exception as e:
        rf_error = str(e)

    if rf_error is None and rf_f1 is not None:
        rf_worse = False
        if rf_baseline_f1 is not None:
            rf_worse = rf_f1 < rf_baseline_f1 if accept_equal else rf_f1 <= rf_baseline_f1
        if rf_worse:
            if rf_old_model is not None:
                joblib.dump(rf_old_model, rf_path)
            if rf_old_le is not None:
                joblib.dump(rf_old_le, rf_le_path)
        else:
            joblib.dump(rf, rf_path)
            joblib.dump(le_rf, rf_le_path)
            rf_baseline_path.write_text(json.dumps({"f1": rf_f1}, indent=2), encoding="utf-8")

    baseline_path.write_text(
        json.dumps({"f1": new_f1, **metrics}, indent=2),
        encoding="utf-8",
    )
    deep_report = _retrain_deep_models(df, num, artifacts_dir, settings, split, feat_cfg)
    payload = {
        "status": "ok",
        "metrics": metrics,
        "baseline_f1": baseline_f1,
        "rf_f1": rf_f1,
        "rf_baseline_f1": rf_baseline_f1,
        "rf_contract": "binary_label_encoder_synced",
        "deep_models": deep_report,
        "if_aggregate": if_agg_report,
    }
    if rf_error is not None:
        payload["rf_status"] = "error"
        payload["rf_reason"] = rf_error
    res = _record(payload, n_rows=n)
    if wm_enabled and wm_path is not None:
        _sz = buffer_resolved.stat().st_size if buffer_resolved.is_file() else None
        _write_watermark_rows(
            wm_path,
            wm_next_rows,
            processed_csv,
            buffer_path=buffer_resolved,
            rotation_generation=read_rotation_generation(buffer_resolved),
            file_size_bytes=_sz,
            head_data_fingerprint=head_fp_open,
            prefix_last_row_fingerprint=fingerprint_prefix_last_row(df_full, wm_next_rows),
            prefix_interior_checksum=prefix_interior_checksum(df_full, wm_next_rows),
        )
    try:
        write_model_status_report(settings, base=root)
    except Exception as e:
        warnings.warn(
            f"Failed to refresh model_status_report after online run: {e}",
            UserWarning,
            stacklevel=2,
        )
    return res


def sleep_loop(
    interval_minutes: int,
    callback,
    max_iterations: int | None = None,
    *,
    initial_delay: bool = False,
) -> None:
    """
    Вызывать ``callback`` каждые ``interval_minutes`` (демо или альтернатива планировщику ОС).

    Параметры
    ----------
    interval_minutes : int
        Интервал в минутах (в ТЗ — 15).
    callback : callable
        Функция без аргументов (например обёртка над ``run_one_retrain_iteration``).
    max_iterations : int | None
        Ограничение числа итераций; ``None`` — бесконечный цикл.
    initial_delay : bool
        Если ``True``, перед первой итерацией будет пауза ``interval_minutes``.
        По умолчанию ``False``: первая итерация запускается сразу (immediate first tick).
    """
    it = 0
    while max_iterations is None or it < max_iterations:
        if initial_delay and it == 0:
            time.sleep(interval_minutes * 60)
        callback()
        it += 1
        if max_iterations is not None and it >= max_iterations:
            break
        time.sleep(interval_minutes * 60)
