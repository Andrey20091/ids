import json
import importlib.util
import sys
from pathlib import Path

import pandas as pd
import pytest
import src.online.retrain_scheduler as retrain_scheduler


@pytest.fixture(autouse=True)
def _clear_ids_project_root_for_realtime_tests(monkeypatch):
    """Соседние тесты могут выставлять IDS_PROJECT_ROOT; realtime грузит settings/features от корня."""
    monkeypatch.delenv("IDS_PROJECT_ROOT", raising=False)


def test_realtime_loop_processes_one_chunk(tmp_path, monkeypatch):
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "05_run_realtime_detection.py"
    spec = importlib.util.spec_from_file_location("realtime_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)

    data_path = tmp_path / "flows.csv"
    out_path = tmp_path / "alerts.json"
    pd.DataFrame({"x": [1, 2, 3], "is_attack": [0, 1, 0]}).to_csv(data_path, index=False)

    def _fake_detect(df, settings, feat_cfg):
        assert not df.empty
        return [{"ip": "1.1.1.1", "threat_score": 90.0}]

    monkeypatch.setattr(module, "_load_detection_callable", lambda: _fake_detect)
    monkeypatch.setattr(module.time, "sleep", lambda *_args, **_kwargs: None)

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            str(script_path),
            "--data",
            str(data_path),
            "--output-alerts",
            str(out_path),
            "--iterations",
            "1",
        ]
        module.main()
    finally:
        sys.argv = old_argv

    assert out_path.is_file()
    alerts = json.loads(out_path.read_text(encoding="utf-8"))
    assert len(alerts) == 1
    assert alerts[0]["ip"] == "1.1.1.1"


def test_realtime_loop_uses_merged_feature_config(tmp_path, monkeypatch):
    repo = Path(__file__).resolve().parents[1]
    script_path = repo / "scripts" / "05_run_realtime_detection.py"
    spec = importlib.util.spec_from_file_location("realtime_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)

    data_path = tmp_path / "flows.csv"
    out_path = tmp_path / "alerts.json"
    # Колонка есть в canonical CICIDS, но не в "ручном" numeric_features.
    pd.DataFrame(
        {
            "Total Length of Fwd Packets": [100.0, 120.0],
            "is_attack": [0, 1],
        }
    ).to_csv(data_path, index=False)

    def _fake_detect(df, settings, feat_cfg):
        assert not df.empty
        assert "Total Length of Fwd Packets" in feat_cfg.get("numeric_features", [])
        return []

    monkeypatch.setattr(module, "_load_detection_callable", lambda: _fake_detect)
    monkeypatch.setattr(module.time, "sleep", lambda *_args, **_kwargs: None)

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            str(script_path),
            "--data",
            str(data_path),
            "--output-alerts",
            str(out_path),
            "--iterations",
            "1",
            "--features-yaml",
            str(repo / "config" / "feature_columns.yaml"),
        ]
        module.main()
    finally:
        sys.argv = old_argv

    assert out_path.is_file()


def test_realtime_loop_can_trigger_auto_online_retrain(tmp_path, monkeypatch):
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "05_run_realtime_detection.py"
    spec = importlib.util.spec_from_file_location("realtime_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)

    data_path = tmp_path / "flows.csv"
    out_path = tmp_path / "alerts.json"
    pd.DataFrame({"x": [1, 2, 3], "is_attack": [0, 1, 0]}).to_csv(data_path, index=False)

    retrain_calls = []

    def _fake_detect(df, settings, feat_cfg):
        return []

    def _fake_retrain(path):
        retrain_calls.append(str(path))
        return {"status": "success"}

    monkeypatch.setattr(module, "_load_detection_callable", lambda: _fake_detect)
    monkeypatch.setattr(retrain_scheduler, "run_one_retrain_iteration", _fake_retrain)
    monkeypatch.setattr(module.time, "sleep", lambda *_args, **_kwargs: None)

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            str(script_path),
            "--data",
            str(data_path),
            "--output-alerts",
            str(out_path),
            "--iterations",
            "3",
            "--auto-online-retrain",
            "--auto-online-every-iters",
            "2",
        ]
        module.main()
    finally:
        sys.argv = old_argv

    assert out_path.is_file()
    assert len(retrain_calls) == 1
    assert retrain_calls[0] == str(data_path)


def test_realtime_loop_processes_only_appended_rows(tmp_path, monkeypatch):
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "05_run_realtime_detection.py"
    spec = importlib.util.spec_from_file_location("realtime_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)

    data_path = tmp_path / "flows.csv"
    out_path = tmp_path / "alerts.json"
    pd.DataFrame({"x": [1, 2], "is_attack": [0, 1]}).to_csv(data_path, index=False)
    seen_chunks = []

    def _fake_detect(df, settings, feat_cfg):
        seen_chunks.append(len(df))
        return [{"ip": "1.1.1.1", "threat_score": 50.0}]

    sleep_calls = {"n": 0}

    def _fake_sleep(*_args, **_kwargs):
        sleep_calls["n"] += 1
        if sleep_calls["n"] == 1:
            pd.DataFrame({"x": [3], "is_attack": [0]}).to_csv(data_path, mode="a", header=False, index=False)

    monkeypatch.setattr(module, "_load_detection_callable", lambda: _fake_detect)
    monkeypatch.setattr(module.time, "sleep", _fake_sleep)

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            str(script_path),
            "--data",
            str(data_path),
            "--output-alerts",
            str(out_path),
            "--iterations",
            "2",
            "--batch-size",
            "10",
        ]
        module.main()
    finally:
        sys.argv = old_argv

    assert seen_chunks == [2, 1]


def test_realtime_loop_handles_file_truncation_reset_offset(tmp_path, monkeypatch):
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "05_run_realtime_detection.py"
    spec = importlib.util.spec_from_file_location("realtime_script", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)

    data_path = tmp_path / "flows.csv"
    out_path = tmp_path / "alerts.json"
    pd.DataFrame({"x": [1, 2], "is_attack": [0, 1]}).to_csv(data_path, index=False)
    seen_chunks = []
    sleep_calls = {"n": 0}

    def _fake_detect(df, settings, feat_cfg):
        seen_chunks.append(len(df))
        return []

    def _fake_sleep(*_args, **_kwargs):
        sleep_calls["n"] += 1
        if sleep_calls["n"] == 1:
            # Simulate log rotation/truncate and new small payload.
            pd.DataFrame({"x": [9], "is_attack": [1]}).to_csv(data_path, index=False)

    monkeypatch.setattr(module, "_load_detection_callable", lambda: _fake_detect)
    monkeypatch.setattr(module.time, "sleep", _fake_sleep)

    old_argv = sys.argv[:]
    try:
        sys.argv = [
            str(script_path),
            "--data",
            str(data_path),
            "--output-alerts",
            str(out_path),
            "--iterations",
            "2",
            "--batch-size",
            "10",
        ]
        module.main()
    finally:
        sys.argv = old_argv

    assert seen_chunks == [2, 1]
