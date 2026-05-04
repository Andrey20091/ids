from pathlib import Path

import pandas as pd

from src.correlation.siem_loader import load_siem_events_ndjson


def test_load_siem_events_ndjson_normalizes_aliases(tmp_path):
    p = tmp_path / "ev.ndjson"
    p.write_text(
        '{"client_ip": "1.1.1.1", "evt": "failed_login"}\n'
        '{"ip": "2.2.2.2", "event_type": "config_change"}\n',
        encoding="utf-8",
    )
    df = load_siem_events_ndjson(p)
    assert len(df) == 2
    assert df["ip"].tolist() == ["1.1.1.1", "2.2.2.2"]
    assert df["event_type"].tolist() == ["failed_login", "config_change"]


def test_load_siem_events_ndjson_skips_bad_lines_and_non_objects(tmp_path):
    """Битый JSON / массив в строке не роняют весь файл — остаются только объекты."""
    p = tmp_path / "mixed.ndjson"
    p.write_text(
        '{"ip": "1.1.1.1", "event_type": "ok"}\n'
        "not json at all\n"
        '{"ip": "2.2.2.2", "event_type": "also_ok"}\n'
        '[1, 2, 3]\n'
        '{"ip": "3.3.3.3", "event_type": "last"}\n',
        encoding="utf-8",
    )
    df = load_siem_events_ndjson(p)
    assert len(df) == 3
    assert df["ip"].tolist() == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_detection_script_load_siem_ndjson_branch(monkeypatch):
    import runpy

    module = runpy.run_path("scripts/03_run_detection_batch.py")
    load_siem = module["_load_siem"]
    root = Path(module["_ROOT"])

    called = {"path": None}

    def _fake_ndjson(path):
        called["path"] = Path(path)
        return pd.DataFrame([{"ip": "9.9.9.9", "event_type": "failed_login"}])

    monkeypatch.setattr(
        "src.correlation.siem_loader.load_siem_events_ndjson",
        _fake_ndjson,
    )

    expected = (root / "storage" / "siem_events_sample.ndjson").resolve()
    settings = {
        "siem": {
            "source": "ndjson_file",
            "ndjson_path": "storage/siem_events_sample.ndjson",
        },
        "paths": {
            "siem_events": "storage/siem_events_sample.json",
            "siem_events_ndjson": "storage/siem_events_sample.ndjson",
        },
    }
    df = load_siem(settings)
    assert not df.empty
    assert called["path"] == expected


def test_repo_ndjson_sample_loads():
    root = Path(__file__).resolve().parents[1]
    p = root / "storage" / "siem_events_sample.ndjson"
    assert p.is_file()
    df = load_siem_events_ndjson(p)
    assert len(df) >= 1
    assert "ip" in df.columns and "event_type" in df.columns


def test_governance_retrain_history_has_iteration_fields(tmp_path, monkeypatch):
    """Smoke: JSONL row includes scheduler/min_samples/deep_validation metadata."""
    import json

    import pandas as pd

    from src.online.retrain_scheduler import run_one_retrain_iteration

    feat = tmp_path / "config" / "feature_columns.yaml"
    feat.parent.mkdir(parents=True, exist_ok=True)
    feat.write_text("numeric_features: [f1, f2]\ntimestamp_column:\n", encoding="utf-8")

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
        "paths": {"artifacts": str(tmp_path / "artifacts"), "storage": "storage"},
        "online": {
            "retrain_interval_minutes": 15,
            "min_samples_retrain": 10,
            "validation_size_ratio": 0.2,
            "if_accept_equal_f1": True,
            "retrain_deep_models": False,
            "deep_validation": {"enabled": True},
        },
        "models": {
            "isolation_forest": {"n_estimators": 10, "contamination": 0.1},
            "random_forest": {"n_estimators": 10, "max_depth": 4, "random_state": 42},
        },
    }
    monkeypatch.setattr("src.online.retrain_scheduler.load_settings", lambda: settings)
    monkeypatch.setattr("src.online.retrain_scheduler.project_root", lambda: tmp_path)

    run_one_retrain_iteration(data_path, artifacts_dir=settings["paths"]["artifacts"])
    hist = tmp_path / "storage" / "retrain_history.jsonl"
    assert hist.is_file()
    last = json.loads(hist.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert last["retrain_interval_minutes"] == 15
    assert last["min_samples_retrain_threshold"] == 10
    assert last["deep_validation_enabled"] is True
    assert "iteration_semantics" in last
