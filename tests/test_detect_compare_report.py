import importlib.util
import json
from argparse import Namespace
from pathlib import Path

import pandas as pd


def _load_detect_script():
    root = Path(__file__).resolve().parents[1]
    path = root / "scripts" / "03_run_detection_batch.py"
    spec = importlib.util.spec_from_file_location("detect_script_mod", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_detect_compare_report_generation(monkeypatch, tmp_path):
    mod = _load_detect_script()

    def _fake_run(df, settings, feat_cfg, no_lstm, no_embedding, l2_only_after_l1, packet_lstm_scores_npz):
        base = {
            "ip": "1.1.1.1",
            "threat_score": 70.0 if l2_only_after_l1 is None else 55.0,
            "severity": "High" if l2_only_after_l1 is None else "Medium",
            "l2_rf_attack_score": 0.7,
            "l2_ae_ratio": 0.2,
            "l2_lstm_attack_score": 0.6,
            "l2_emb_attack_score": 0.5,
            "l2_hdr_cnn_attack_score": 0.4,
            "l2_lstm_pkt_score": 0.0,
        }
        return [base for _ in range(3 if l2_only_after_l1 is None else 5)]

    monkeypatch.setattr(mod, "run_detection_on_dataframe", _fake_run)
    args = Namespace(
        no_lstm=False,
        no_embedding=False,
        packet_lstm_scores="",
        data="data/processed/flows.csv",
    )
    settings = {"paths": {"storage": str(tmp_path / "storage")}}
    df = pd.DataFrame({"f1": [1.0, 2.0, 3.0]})
    out = tmp_path / "cmp.json"
    path = mod._write_detect_compare_report(df, settings=settings, feat_cfg={"numeric_features": ["f1"]}, args=args, output_path=str(out))
    assert path.is_file()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["default_l1_gated"]["alert_count"] == 3
    assert payload["parallel_l2"]["alert_count"] == 5
    assert "mode_guidance" in payload
