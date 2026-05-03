from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from src.online import retrain_scheduler as rs
from src.online.buffer_integrity import (
    fingerprint_data_row,
    fingerprint_first_data_row,
    prefix_interior_checksum,
)
from src.online.buffer_rotation import buffer_meta_path, increment_rotation_generation


def _settings_for_tmp(tmp_path: Path) -> dict:
    return {
        "paths": {
            "artifacts": str(tmp_path / "artifacts"),
            "storage": str(tmp_path / "storage"),
            "flows_online_buffer": str(tmp_path / "flows_online_buffer.csv"),
        },
        "online": {
            "retrain_interval_minutes": 15,
            "min_samples_retrain": 5,
            "validation_size_ratio": 0.2,
            "if_accept_equal_f1": True,
            "watermark": {
                "enabled": True,
                "state_path": str(tmp_path / "storage" / "online_buffer_watermark.json"),
            },
            "agg_if_validation": {"enabled": False},
            "deep_validation": {"enabled": False},
            "retrain_deep_models": False,
        },
        "models": {
            "isolation_forest": {"n_estimators": 10, "contamination": 0.05, "random_state": 42},
            "random_forest": {"n_estimators": 10, "max_depth": 6, "random_state": 42},
        },
    }


def _write_min_features_yaml(tmp_path: Path) -> None:
    p = tmp_path / "config" / "feature_columns.yaml"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("numeric_features: [a]\ntimestamp_column:\n", encoding="utf-8")


def test_online_watermark_skips_when_no_new_rows(tmp_path, monkeypatch):
    data_path = tmp_path / "flows_online_buffer.csv"
    pd.DataFrame({"a": [1, 2, 3], "is_attack": [0, 1, 0]}).to_csv(data_path, index=False)
    st = tmp_path / "storage" / "online_buffer_watermark.json"
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(
        json.dumps({"rows_processed": 3, "rotation_generation": 0}),
        encoding="utf-8",
    )

    monkeypatch.setattr(rs, "load_settings", lambda *_a, **_k: _settings_for_tmp(tmp_path))
    monkeypatch.setattr(rs, "project_root", lambda: tmp_path)
    monkeypatch.setattr(rs, "get_training_policy", lambda *_a, **_k: {"require_baseline_before_online": False})
    monkeypatch.setattr(rs, "write_model_status_report", lambda *_a, **_k: None)

    out = rs.run_one_retrain_iteration(data_path, artifacts_dir=tmp_path / "artifacts")
    assert out["status"] == "skipped"
    assert "no new rows" in str(out.get("reason", "")).lower()


def test_online_watermark_resets_on_truncate(tmp_path, monkeypatch):
    _write_min_features_yaml(tmp_path)
    data_path = tmp_path / "flows_online_buffer.csv"
    pd.DataFrame({"a": [1, 2], "is_attack": [0, 1]}).to_csv(data_path, index=False)
    st = tmp_path / "storage" / "online_buffer_watermark.json"
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(
        json.dumps({"rows_processed": 100, "rotation_generation": 0}),
        encoding="utf-8",
    )

    monkeypatch.setattr(rs, "load_settings", lambda *_a, **_k: _settings_for_tmp(tmp_path))
    monkeypatch.setattr(rs, "project_root", lambda: tmp_path)
    monkeypatch.setattr(rs, "get_training_policy", lambda *_a, **_k: {"require_baseline_before_online": False})
    monkeypatch.setattr(rs, "write_model_status_report", lambda *_a, **_k: None)

    out = rs.run_one_retrain_iteration(data_path, artifacts_dir=tmp_path / "artifacts")
    assert out["status"] == "skipped"
    assert "need >=" in str(out.get("reason", "")).lower()


def test_online_watermark_resets_when_rotation_generation_changes(tmp_path, monkeypatch):
    """meta.rotation_generation выше, чем в watermark — обрабатываем буфер с начала (после ротации)."""
    _write_min_features_yaml(tmp_path)
    data_path = tmp_path / "flows_online_buffer.csv"
    n = 24
    pd.DataFrame({"a": list(range(n)), "is_attack": [i % 2 for i in range(n)]}).to_csv(data_path, index=False)
    meta = buffer_meta_path(data_path)
    meta.parent.mkdir(parents=True, exist_ok=True)
    meta.write_text(json.dumps({"rotation_generation": 3}), encoding="utf-8")
    st = tmp_path / "storage" / "online_buffer_watermark.json"
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(
        json.dumps({"rows_processed": 20, "rotation_generation": 1}),
        encoding="utf-8",
    )

    monkeypatch.setattr(rs, "load_settings", lambda *_a, **_k: _settings_for_tmp(tmp_path))
    monkeypatch.setattr(rs, "project_root", lambda: tmp_path)
    monkeypatch.setattr(rs, "get_training_policy", lambda *_a, **_k: {"require_baseline_before_online": False})
    monkeypatch.setattr(rs, "write_model_status_report", lambda *_a, **_k: None)

    out = rs.run_one_retrain_iteration(data_path, artifacts_dir=tmp_path / "artifacts")
    assert out["status"] == "ok"
    payload = json.loads(st.read_text(encoding="utf-8"))
    assert payload.get("rotation_generation") == 3
    assert payload.get("rows_processed") == n


def test_increment_rotation_generation_updates_meta(tmp_path):
    p = tmp_path / "flows_online_buffer.csv"
    p.write_text("a,b\n1,2\n", encoding="utf-8")
    assert increment_rotation_generation(p) == 1
    assert increment_rotation_generation(p) == 2
    data = json.loads(buffer_meta_path(p).read_text(encoding="utf-8"))
    assert data["rotation_generation"] == 2


def test_online_watermark_resets_when_interior_prefix_row_changed(tmp_path, monkeypatch):
    """Меняется только «внутренняя» строка префикса (не 0 и не rows_processed−1)."""
    _write_min_features_yaml(tmp_path)
    data_path = tmp_path / "flows_online_buffer.csv"
    n = 8
    k = 6
    base = pd.DataFrame({"a": list(range(n)), "is_attack": [i % 2 for i in range(n)]})
    base.to_csv(data_path, index=False)
    st = tmp_path / "storage" / "online_buffer_watermark.json"
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(
        json.dumps(
            {
                "rows_processed": k,
                "rotation_generation": 0,
                "head_data_fingerprint": fingerprint_first_data_row(base),
                "prefix_last_row_fingerprint": fingerprint_data_row(base.iloc[k - 1]),
                "prefix_interior_checksum": prefix_interior_checksum(base, k),
            }
        ),
        encoding="utf-8",
    )
    changed = base.copy()
    changed.loc[k // 2, "a"] = 99999
    changed.to_csv(data_path, index=False)

    monkeypatch.setattr(rs, "load_settings", lambda *_a, **_k: _settings_for_tmp(tmp_path))
    monkeypatch.setattr(rs, "project_root", lambda: tmp_path)
    monkeypatch.setattr(rs, "get_training_policy", lambda *_a, **_k: {"require_baseline_before_online": False})
    monkeypatch.setattr(rs, "write_model_status_report", lambda *_a, **_k: None)

    out = rs.run_one_retrain_iteration(data_path, artifacts_dir=tmp_path / "artifacts")
    assert out["status"] == "ok"
    payload = json.loads(st.read_text(encoding="utf-8"))
    assert payload.get("rows_processed") == n


def test_online_watermark_resets_when_prefix_boundary_row_changes(tmp_path, monkeypatch):
    """Изменена строка на границе обработанного префикса — сброс anchor."""
    _write_min_features_yaml(tmp_path)
    data_path = tmp_path / "flows_online_buffer.csv"
    n = 12
    base = pd.DataFrame({"a": list(range(n)), "is_attack": [i % 2 for i in range(n)]})
    base.to_csv(data_path, index=False)
    st = tmp_path / "storage" / "online_buffer_watermark.json"
    st.parent.mkdir(parents=True, exist_ok=True)
    rows_done = 5
    st.write_text(
        json.dumps(
            {
                "rows_processed": rows_done,
                "rotation_generation": 0,
                "head_data_fingerprint": fingerprint_first_data_row(base),
                "prefix_last_row_fingerprint": fingerprint_data_row(base.iloc[rows_done - 1]),
            }
        ),
        encoding="utf-8",
    )
    changed = base.copy()
    changed.loc[4, "a"] = 99999
    changed.to_csv(data_path, index=False)

    monkeypatch.setattr(rs, "load_settings", lambda *_a, **_k: _settings_for_tmp(tmp_path))
    monkeypatch.setattr(rs, "project_root", lambda: tmp_path)
    monkeypatch.setattr(rs, "get_training_policy", lambda *_a, **_k: {"require_baseline_before_online": False})
    monkeypatch.setattr(rs, "write_model_status_report", lambda *_a, **_k: None)

    out = rs.run_one_retrain_iteration(data_path, artifacts_dir=tmp_path / "artifacts")
    assert out["status"] == "ok"
    payload = json.loads(st.read_text(encoding="utf-8"))
    assert payload.get("rows_processed") == n


def test_online_watermark_resets_when_head_fingerprint_mismatch(tmp_path, monkeypatch):
    """Та же generation, но сменилась первая строка буфера — сброс anchor (ручная правка)."""
    _write_min_features_yaml(tmp_path)
    data_path = tmp_path / "flows_online_buffer.csv"
    n = 20
    pd.DataFrame({"a": list(range(n)), "is_attack": [i % 2 for i in range(n)]}).to_csv(data_path, index=False)
    st = tmp_path / "storage" / "online_buffer_watermark.json"
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(
        json.dumps(
            {
                "rows_processed": 18,
                "rotation_generation": 0,
                "head_data_fingerprint": "deadbeef" * 8,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(rs, "load_settings", lambda *_a, **_k: _settings_for_tmp(tmp_path))
    monkeypatch.setattr(rs, "project_root", lambda: tmp_path)
    monkeypatch.setattr(rs, "get_training_policy", lambda *_a, **_k: {"require_baseline_before_online": False})
    monkeypatch.setattr(rs, "write_model_status_report", lambda *_a, **_k: None)

    out = rs.run_one_retrain_iteration(data_path, artifacts_dir=tmp_path / "artifacts")
    assert out["status"] == "ok"
    payload = json.loads(st.read_text(encoding="utf-8"))
    assert payload.get("rows_processed") == n
    assert payload.get("head_data_fingerprint") not in (None, "deadbeef" * 8)
