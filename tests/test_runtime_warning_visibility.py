import json
from pathlib import Path

import pandas as pd
import pytest

from src.features.aggregate_if_training import agg_if_alignment_f1
from src.governance.storage import load_jsonl
from src.utils.model_health import load_or_init_baselines


def test_load_jsonl_warns_on_bad_rows(tmp_path):
    p = tmp_path / "broken.jsonl"
    p.write_text('{"ok":1}\n{bad}\n{"ok":2}\n', encoding="utf-8")
    with pytest.warns(UserWarning, match="Skipped 1 malformed JSONL rows"):
        rows = load_jsonl(p)
    assert len(rows) == 2


def test_agg_if_alignment_warns_on_internal_error():
    class _BrokenModel:
        def predict(self, _x):
            raise RuntimeError("boom")

    bucket_ts = pd.Series(pd.date_range("2026-01-01", periods=3, freq="min"))
    agg_num = pd.DataFrame({"a": [1.0, 2.0, 3.0]})
    bucket_attack = pd.Series([0, 1, 0], index=pd.date_range("2026-01-01", periods=3, freq="min"))
    with pytest.warns(UserWarning, match="agg_if_alignment_f1 fallback"):
        out = agg_if_alignment_f1(bucket_ts, agg_num, _BrokenModel(), bucket_attack)
    assert out["f1"] == 0.0
    assert "error" in out


def test_model_baselines_warn_on_corrupt_json(tmp_path):
    settings = {"paths": {"storage": str(tmp_path / "storage")}}
    bpath = Path(settings["paths"]["storage"]) / "model_baselines.json"
    bpath.parent.mkdir(parents=True, exist_ok=True)
    bpath.write_text("{broken", encoding="utf-8")
    with pytest.warns(UserWarning, match="Failed to read model baselines"):
        path, data = load_or_init_baselines(settings, tmp_path)
    assert path == bpath
    assert isinstance(data, dict)
