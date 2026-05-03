import json
from pathlib import Path

import yaml

from src.features.feature_config import load_merged_feature_config
from src.utils.model_health import write_model_status_report
from src.utils_config import project_root, resolve_from_project_root


def test_project_root_respects_ids_project_root(monkeypatch, tmp_path):
    monkeypatch.setenv("IDS_PROJECT_ROOT", str(tmp_path))
    assert project_root() == tmp_path.resolve()
    rel = resolve_from_project_root("storage/model_status_report.json")
    assert rel == tmp_path.resolve() / "storage" / "model_status_report.json"


def test_feature_config_uses_local_canonical_next_to_features(tmp_path):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "cicids2017_canonical_numeric.yaml").write_text(
        yaml.safe_dump({"numeric_features": ["canon_a", "canon_b"]}, sort_keys=False),
        encoding="utf-8",
    )
    (cfg_dir / "feature_columns.yaml").write_text(
        yaml.safe_dump(
            {
                "numeric_features": ["own_x"],
                "cicids2017": {"include_all_canonical_numeric": True, "canonical_exclude": []},
                "header_raw_bytes": {"enabled": False},
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    cfg = load_merged_feature_config(cfg_dir / "feature_columns.yaml")
    assert "canon_a" in cfg["numeric_features"]
    assert "canon_b" in cfg["numeric_features"]


def test_model_status_report_defaults_to_project_root(monkeypatch, tmp_path):
    monkeypatch.setenv("IDS_PROJECT_ROOT", str(tmp_path))
    (tmp_path / "artifacts").mkdir(parents=True, exist_ok=True)
    settings = {"paths": {"storage": "storage", "artifacts": "artifacts"}}
    out = write_model_status_report(settings)
    assert out == tmp_path / "storage" / "model_status_report.json"
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["alerts_path"].startswith(str(tmp_path))
