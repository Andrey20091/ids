import importlib.util
import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from src.online.retrain_scheduler import run_one_retrain_iteration


def _run_script(path: Path, argv: list[str]) -> None:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    old_argv = sys.argv[:]
    try:
        sys.argv = [str(path), *argv]
        module.main()
    finally:
        sys.argv = old_argv


def test_incident_sync_and_status(tmp_path):
    alerts = [
        {"ip": "1.2.3.4", "ts": "2026-01-01 00:00:00", "threat_score": 77.0, "recommendation": "test"}
    ]
    alerts_path = tmp_path / "alerts.json"
    alerts_path.write_text(json.dumps(alerts), encoding="utf-8")
    incidents_path = tmp_path / "incidents.jsonl"
    actions_path = tmp_path / "incident_actions.jsonl"

    root = Path(__file__).resolve().parents[1]
    _run_script(
        root / "scripts" / "08_sync_incidents.py",
        ["--alerts", str(alerts_path), "--incidents", str(incidents_path)],
    )

    rows = incidents_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(rows) == 1
    incident = json.loads(rows[0])
    inc_id = incident["incident_id"]

    _run_script(
        root / "scripts" / "09_set_incident_status.py",
        [
            "--incident-id",
            inc_id,
            "--status",
            "in_progress",
            "--incidents",
            str(incidents_path),
            "--actions",
            str(actions_path),
        ],
    )
    updated = json.loads(incidents_path.read_text(encoding="utf-8").strip().splitlines()[0])
    assert updated["status"] == "in_progress"
    assert actions_path.is_file()


def _write_min_features_yaml(tmp: Path) -> None:
    p = tmp / "config" / "feature_columns.yaml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("numeric_features: [f1, f2]\ntimestamp_column:\n", encoding="utf-8")


def test_online_retrain_writes_history(tmp_path, monkeypatch):
    _write_min_features_yaml(tmp_path)
    data_path = tmp_path / "flows.csv"
    n = 40
    pd.DataFrame(
        {
            "f1": [float(i) for i in range(n)],
            "f2": [float(i % 7) for i in range(n)],
            "is_attack": [1 if i % 5 == 0 else 0 for i in range(n)],
        }
    ).to_csv(data_path, index=False)

    settings = {
        "paths": {"artifacts": str(tmp_path / "artifacts"), "storage": str(tmp_path / "storage")},
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
    monkeypatch.setattr("src.online.retrain_scheduler.project_root", lambda: tmp_path)
    out = run_one_retrain_iteration(data_path, artifacts_dir=settings["paths"]["artifacts"])
    assert out["status"] == "ok"
    hist = tmp_path / "storage" / "retrain_history.jsonl"
    assert hist.is_file()
    last = json.loads(hist.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert last["result"] == "ok"


def test_sandbox_eval_report(tmp_path):
    root = Path(__file__).resolve().parents[1]
    x = pd.DataFrame({"a": [0, 1, 0, 1, 0, 1], "b": [0, 0, 1, 1, 0, 1]})
    y = pd.Series([0, 1, 0, 1, 0, 1])

    baseline = RandomForestClassifier(n_estimators=10, random_state=1).fit(x, y)
    candidate = RandomForestClassifier(n_estimators=20, random_state=2).fit(x, y)
    art = tmp_path / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    base_path = art / "rf_base.joblib"
    cand_path = art / "rf_cand.joblib"
    joblib.dump(baseline, base_path)
    joblib.dump(candidate, cand_path)

    reg = {
        "active_model_set_id": "base",
        "model_sets": [
            {"model_set_id": "base", "status": "production", "paths": {"rf": str(base_path)}},
            {"model_set_id": "cand", "status": "candidate", "paths": {"rf": str(cand_path)}},
        ],
    }
    registry_path = art / "model_registry.json"
    registry_path.write_text(json.dumps(reg), encoding="utf-8")
    labels = x.copy()
    labels["is_attack"] = y
    labels_path = tmp_path / "labels.csv"
    labels.to_csv(labels_path, index=False)
    report_path = tmp_path / "sandbox_reports.jsonl"

    _run_script(
        root / "scripts" / "12_sandbox_eval.py",
        [
            "--labels",
            str(labels_path),
            "--registry",
            str(registry_path),
            "--reports",
            str(report_path),
            "--candidate-model-set-id",
            "cand",
            "--min-delta-f1",
            "0.0",
            "--min-precision",
            "0.0",
        ],
    )
    assert report_path.is_file()
    row = json.loads(report_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert row["candidate_model_set_id"] == "cand"

