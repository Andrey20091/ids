# =============================================================================
# Скрипт 12: оценка candidate vs active модели по labels_dataset.csv
# =============================================================================
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.governance.storage import append_jsonl, load_json, save_json, utc_now_iso


def _ensure_registry(path: Path) -> dict:
    reg = load_json(path, default={})
    if reg:
        return reg
    default = {
        "active_model_set_id": "model_default",
        "model_sets": [
            {
                "model_set_id": "model_default",
                "status": "production",
                "created_at": utc_now_iso(),
                "paths": {"rf": "artifacts/rf_model.joblib"},
                "metrics": {},
                "approved_by": "bootstrap",
                "approved_at": utc_now_iso(),
            }
        ],
    }
    save_json(path, default)
    return default


def _model_path(reg: dict, model_set_id: str) -> Path:
    for m in reg.get("model_sets", []):
        if str(m.get("model_set_id")) == model_set_id:
            rf_rel = str(m.get("paths", {}).get("rf", "artifacts/rf_model.joblib"))
            p = Path(rf_rel)
            return p if p.is_absolute() else (_ROOT / p)
    raise SystemExit(f"Model set not found: {model_set_id}")


def _metrics(y_true: pd.Series, y_pred: pd.Series) -> dict:
    def _bin(s: pd.Series) -> pd.Series:
        if pd.api.types.is_numeric_dtype(s):
            return s.astype(float).gt(0).astype(int)
        t = s.astype(str).str.upper()
        return t.ne("BENIGN").astype(int)

    y_t = _bin(y_true)
    y_p = _bin(y_pred)
    return {
        "f1": float(f1_score(y_t, y_p, zero_division=0)),
        "precision": float(precision_score(y_t, y_p, zero_division=0)),
        "recall": float(recall_score(y_t, y_p, zero_division=0)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate candidate model set against active baseline")
    parser.add_argument("--labels", default=str(_ROOT / "storage/labels_dataset.csv"))
    parser.add_argument("--registry", default=str(_ROOT / "artifacts/model_registry.json"))
    parser.add_argument("--reports", default=str(_ROOT / "storage/sandbox_reports.jsonl"))
    parser.add_argument("--candidate-model-set-id", required=True)
    parser.add_argument("--min-delta-f1", type=float, default=0.01)
    parser.add_argument("--min-precision", type=float, default=0.65)
    args = parser.parse_args()

    labels_path = Path(args.labels) if Path(args.labels).is_absolute() else (_ROOT / args.labels)
    if not labels_path.is_file():
        raise SystemExit(f"Labels file not found: {labels_path}")
    df = pd.read_csv(labels_path)
    if "is_attack" not in df.columns:
        raise SystemExit("labels_dataset must contain is_attack column")

    reg_path = Path(args.registry) if Path(args.registry).is_absolute() else (_ROOT / args.registry)
    reg = _ensure_registry(reg_path)
    active_id = str(reg.get("active_model_set_id", ""))
    if not active_id:
        raise SystemExit("Registry missing active_model_set_id")
    candidate_id = args.candidate_model_set_id

    active_model = joblib.load(_model_path(reg, active_id))
    candidate_model = joblib.load(_model_path(reg, candidate_id))

    def _select_features(model) -> list[str]:
        if hasattr(model, "feature_names_in_"):
            return [str(c) for c in model.feature_names_in_]
        return [c for c in df.columns if c not in {"is_attack", "sample_id", "incident_id", "label_source", "imported_at", "comment", "analyst", "attack_family", "ts", "ip"}]

    feat_base = _select_features(active_model)
    feat_cand = _select_features(candidate_model)
    feat = [c for c in feat_base if c in feat_cand and c in df.columns]
    if not feat:
        raise SystemExit("No compatible feature columns between labels dataset and model feature_names_in_")
    X = df[feat].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    y = df["is_attack"].astype(int)

    m_base = _metrics(y, pd.Series(active_model.predict(X)))
    m_cand = _metrics(y, pd.Series(candidate_model.predict(X)))
    delta_f1 = float(m_cand["f1"] - m_base["f1"])
    decision = "ready_for_approval" if (delta_f1 >= args.min_delta_f1 and m_cand["precision"] >= args.min_precision) else "rejected"

    now = utc_now_iso()
    report = {
        "sandbox_run_id": f"sb_{now.replace(':', '').replace('-', '').replace('T', '_').replace('Z', '')}",
        "candidate_model_set_id": candidate_id,
        "baseline_model_set_id": active_id,
        "dataset_ref": str(labels_path),
        "metrics": {"candidate": m_cand, "baseline": m_base, "delta_f1": delta_f1},
        "decision": decision,
        "policy": {"min_delta_f1": args.min_delta_f1, "min_precision": args.min_precision},
        "created_at": now,
    }
    rep_path = Path(args.reports) if Path(args.reports).is_absolute() else (_ROOT / args.reports)
    append_jsonl(rep_path, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

