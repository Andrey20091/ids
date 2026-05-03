from __future__ import annotations

import hashlib
import json
import subprocess
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
from src.utils_config import project_root


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ts_token() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def settings_hash(settings: dict[str, Any]) -> str:
    payload = json.dumps(settings, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def git_hash(root: Path) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
        return out or None
    except Exception:
        return None


def _base_root() -> Path:
    return project_root()


def _resolve_path(base: Path, p: str | Path) -> Path:
    pp = Path(p)
    return pp if pp.is_absolute() else base / pp


def storage_dir(settings: dict[str, Any], base: Path | None = None) -> Path:
    base = base or _base_root()
    rel = settings.get("paths", {}).get("storage", "storage")
    out = _resolve_path(base, rel)
    out.mkdir(parents=True, exist_ok=True)
    return out


def artifacts_dir(settings: dict[str, Any], base: Path | None = None) -> Path:
    base = base or _base_root()
    rel = settings.get("paths", {}).get("artifacts", "artifacts")
    out = _resolve_path(base, rel)
    out.mkdir(parents=True, exist_ok=True)
    return out


def train_reports_dir(settings: dict[str, Any], base: Path | None = None) -> Path:
    out = storage_dir(settings, base) / "train_reports"
    out.mkdir(parents=True, exist_ok=True)
    return out


def json_write(path: Path, payload: dict[str, Any] | list[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def hb_signal_quality(df: pd.DataFrame, hb_cols: list[str]) -> dict[str, Any]:
    if not hb_cols:
        return {
            "hb_columns_total": 0,
            "hb_columns_present": 0,
            "nonzero_fraction": 0.0,
            "variance_mean": 0.0,
            "signal_quality": "missing",
            "warning": "hb_* columns are not configured.",
        }
    present = [c for c in hb_cols if c in df.columns]
    if not present:
        return {
            "hb_columns_total": len(hb_cols),
            "hb_columns_present": 0,
            "nonzero_fraction": 0.0,
            "variance_mean": 0.0,
            "signal_quality": "missing",
            "warning": "hb_* columns are configured but absent in dataset.",
        }
    sub = df[present].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    total = max(float(sub.shape[0] * sub.shape[1]), 1.0)
    nonzero_fraction = float((sub != 0.0).sum().sum()) / total
    variance_mean = float(sub.var(axis=0).fillna(0.0).mean())
    if nonzero_fraction <= 0.0001 or variance_mean <= 1e-10:
        return {
            "hb_columns_total": len(hb_cols),
            "hb_columns_present": len(present),
            "nonzero_fraction": round(nonzero_fraction, 8),
            "variance_mean": variance_mean,
            "signal_quality": "constant_or_empty",
            "warning": "hb_* signal is constant/empty; raw_header_cnn may become near-constant in detect.",
        }
    if nonzero_fraction < 0.01:
        return {
            "hb_columns_total": len(hb_cols),
            "hb_columns_present": len(present),
            "nonzero_fraction": round(nonzero_fraction, 8),
            "variance_mean": variance_mean,
            "signal_quality": "weak",
            "warning": "hb_* signal is very sparse; check NPZ alignment and pcap coverage.",
        }
    return {
        "hb_columns_total": len(hb_cols),
        "hb_columns_present": len(present),
        "nonzero_fraction": round(nonzero_fraction, 8),
        "variance_mean": variance_mean,
        "signal_quality": "good",
        "warning": "",
    }


def _default_baselines(settings: dict[str, Any]) -> dict[str, Any]:
    dv = settings.get("online", {}).get("deep_validation", {}) or {}
    return {
        "autoencoder": {
            "metric": "val_mse_mean",
            "direction": "lower_is_better",
            "reference": None,
            "tolerance_ratio_up": float(dv.get("ae_max_val_mse_ratio", 1.12)),
        },
        "lstm": {
            "metric": "val_f1",
            "direction": "higher_is_better",
            "reference": None,
            "tolerance_delta_down": abs(float(dv.get("lstm_min_val_f1_vs_baseline", -0.02))),
        },
        "embedding": {
            "metric": "val_acc",
            "direction": "higher_is_better",
            "reference": None,
            "tolerance_delta_down": abs(float(dv.get("embedding_min_val_acc_vs_baseline", -0.02))),
        },
    }


def load_or_init_baselines(settings: dict[str, Any], base: Path | None = None) -> tuple[Path, dict[str, Any]]:
    sdir = storage_dir(settings, base)
    path = sdir / "model_baselines.json"
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return path, data
        except Exception as e:
            warnings.warn(
                f"Failed to read model baselines from {path}: {e}. Reinitializing defaults.",
                UserWarning,
                stacklevel=2,
            )
    data = _default_baselines(settings)
    json_write(path, data)
    return path, data


def assess_deep_health(
    model_name: str,
    metrics: dict[str, Any],
    baselines: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    cur = dict(baselines)
    conf = dict(cur.get(model_name, {}))
    metric_name = conf.get("metric")
    if not metric_name:
        return "warning", "baseline config missing", cur
    val = metrics.get(metric_name)
    if val is None:
        return "warning", f"metric {metric_name} is missing", cur
    val_f = float(val)
    ref = conf.get("reference")
    if ref is None:
        conf["reference"] = val_f
        conf["reference_updated_at"] = utc_now_iso()
        cur[model_name] = conf
        return "healthy", "baseline initialized from current metric", cur

    ref_f = float(ref)
    if conf.get("direction") == "lower_is_better":
        ratio = float(conf.get("tolerance_ratio_up", 1.12))
        ok = val_f <= (ref_f * ratio)
        return ("healthy" if ok else "degraded"), f"{metric_name}={val_f:.6f}, baseline={ref_f:.6f}", cur
    delta = float(conf.get("tolerance_delta_down", 0.02))
    ok = val_f >= (ref_f - delta)
    return ("healthy" if ok else "degraded"), f"{metric_name}={val_f:.6f}, baseline={ref_f:.6f}", cur


def summarize_alert_usage(alerts_path: Path) -> dict[str, Any]:
    if not alerts_path.is_file():
        return {}
    try:
        rows = json.loads(alerts_path.read_text(encoding="utf-8"))
    except Exception as e:
        warnings.warn(
            f"Failed to parse alerts file {alerts_path}: {e}. Model usage metrics may be stale.",
            UserWarning,
            stacklevel=2,
        )
        return {"_error": str(e)}
    if not isinstance(rows, list) or not rows:
        return {}
    df = pd.DataFrame(rows)
    if df.empty:
        return {}

    out: dict[str, Any] = {}
    col_map = {
        "rf": "l2_rf_attack_score",
        "ae": "l2_ae_ratio",
        "lstm": "l2_lstm_attack_score",
        "embedding": "l2_emb_attack_score",
        "raw_header_cnn": "l2_hdr_cnn_attack_score",
        "lstm_packets": "l2_lstm_pkt_score",
    }
    for name, col in col_map.items():
        if col not in df.columns:
            out[name] = {"used": False, "reason": f"column {col} missing in alerts"}
            continue
        s = pd.to_numeric(df[col], errors="coerce").fillna(0.0)
        non_null = int(s.notna().sum())
        non_zero = int((s.abs() > 1e-12).sum())
        std = float(s.std()) if len(s) > 1 else 0.0
        out[name] = {
            "used": bool(non_zero > 0),
            "non_zero_count": non_zero,
            "mean": float(s.mean()),
            "std": std,
            "is_constant": bool(std < 1e-12),
        }
    if "l1_triggered" in df.columns:
        s = df["l1_triggered"].fillna(False).astype(bool)
        info = {"used": True, "true_count": int(s.sum()), "rows": int(len(s))}
        out["if_l1"] = info
        out["if_flow"] = info
        out["if_agg"] = info
    return out


def _artifact_info(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"artifact_exists": False, "artifact_path": str(path), "size_bytes": 0, "mtime": None}
    st = path.stat()
    return {
        "artifact_exists": True,
        "artifact_path": str(path),
        "size_bytes": int(st.st_size),
        "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
    }


def write_model_status_report(
    settings: dict[str, Any],
    *,
    last_train_metrics: dict[str, Any] | None = None,
    base: Path | None = None,
) -> Path:
    root = base or _base_root()
    sdir = storage_dir(settings, root)
    art = artifacts_dir(settings, root)
    reports = train_reports_dir(settings, root)
    alerts_path = sdir / "alerts_latest.json"
    hist_path = sdir / "retrain_history.jsonl"
    usage = summarize_alert_usage(alerts_path)

    last_online_global = {"status": None, "reason": ""}
    per_model_online: dict[str, dict[str, Any]] = {}
    if hist_path.is_file():
        rows = [x for x in hist_path.read_text(encoding="utf-8").splitlines() if x.strip()]
        if rows:
            try:
                obj = json.loads(rows[-1])
                last_online_global = {"status": obj.get("result"), "reason": obj.get("reason", "")}
                if obj.get("result") in ("ok", "rejected", "skipped"):
                    for name in ("if_flow", "if_agg"):
                        per_model_online[name] = dict(last_online_global)
                if obj.get("rf_f1") is not None or obj.get("rf_baseline_f1") is not None:
                    per_model_online["rf"] = {
                        "status": "ok" if obj.get("result") == "ok" else obj.get("result"),
                        "reason": "" if obj.get("result") == "ok" else obj.get("reason", ""),
                    }
                deep_obj = obj.get("deep_models")
                if isinstance(deep_obj, dict):
                    for name in ("ae", "lstm", "embedding", "raw_header_cnn"):
                        model_part = deep_obj.get(name)
                        if isinstance(model_part, dict):
                            per_model_online[name] = {
                                "status": model_part.get("status"),
                                "reason": model_part.get("reason", ""),
                            }
                        elif isinstance(model_part, str):
                            per_model_online[name] = {"status": "info", "reason": model_part}
            except Exception as e:
                warnings.warn(
                    f"Failed to parse last retrain history record in {hist_path}: {e}.",
                    UserWarning,
                    stacklevel=2,
                )
                last_online_global = {"status": "error", "reason": f"history parse failed: {e}"}

    metrics_from_latest = dict(last_train_metrics or {})
    latest_train_model_flags: dict[str, Any] = {}
    if not metrics_from_latest:
        latest = sorted(reports.glob("train_report_*.json"))
        if latest:
            try:
                tr = json.loads(latest[-1].read_text(encoding="utf-8"))
                m = tr.get("models", {})
                for name in ("rf", "if_flow", "if_agg", "ae", "lstm", "embedding", "raw_header_cnn", "lstm_packets"):
                    metrics_from_latest[name] = dict(m.get(name, {}).get("metrics", {}))
                    latest_train_model_flags[name] = m.get(name, {})
            except Exception as e:
                warnings.warn(
                    f"Failed to parse latest train report {latest[-1]}: {e}.",
                    UserWarning,
                    stacklevel=2,
                )

    model_defs = {
        "rf": ["rf_model.joblib", "rf_label_encoder.joblib"],
        "if_flow": ["if_model.joblib"],
        "if_agg": ["if_agg_model.joblib"],
        "ae": ["ae_model.pt"],
        "lstm": ["lstm_model.pt", "lstm_label_encoder.joblib"],
        "embedding": ["embedding_classifier.pt", "embedding_proto_encoder.joblib", "embedding_port_encoder.joblib"],
        "raw_header_cnn": ["raw_header_cnn.pt", "raw_header_cnn_label_encoder.joblib"],
        "lstm_packets": ["lstm_packets_model.pt"],
    }
    models: list[dict[str, Any]] = []
    for name, files in model_defs.items():
        infos = [_artifact_info(art / f) for f in files]
        ready = all(i["artifact_exists"] for i in infos)
        tr_flag = latest_train_model_flags.get(name, {})
        if isinstance(tr_flag, dict) and "detect_participation_ready" in tr_flag:
            ready = bool(tr_flag.get("detect_participation_ready"))
        m = {
            "model": name,
            "ready_for_detect": ready,
            "artifacts": infos,
            "last_train_metrics": metrics_from_latest.get(name, {}),
            "used_in_last_detect": bool(usage.get(name, {}).get("used", False)),
            "last_online_outcome": per_model_online.get(name),
        }
        models.append(m)

    payload = {
        "timestamp": utc_now_iso(),
        "git_hash": git_hash(root),
        "alerts_path": str(alerts_path),
        "online_outcome_global": last_online_global,
        "usage_parse_error": usage.get("_error") if isinstance(usage, dict) else None,
        "models": models,
    }
    stable = sdir / "model_status_report.json"
    json_write(stable, payload)
    stamped = reports / f"model_status_report_{ts_token()}.json"
    json_write(stamped, payload)
    return stable
