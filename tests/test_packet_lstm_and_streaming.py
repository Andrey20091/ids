# =============================================================================
# Склейка packet-LSTM по flow_key; detect без optional артефактов.
# =============================================================================
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

import importlib.util

from src.pipeline.ensemble_orchestrator import run_cascade


def _load_03():
    root = Path(__file__).resolve().parents[1]
    p = root / "scripts" / "03_run_detection_batch.py"
    spec = importlib.util.spec_from_file_location("run03", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_packet_lstm_scores_from_npz_merges_by_key():
    mod = _load_03()
    fn = mod._packet_lstm_scores_from_npz
    df = pd.DataFrame(
        {
            "a": [1, 2],
        }
    )
    df["flow_key"] = ["k1|1|k2|2|TCP", "x|0|y|0|UDP"]
    root = Path(__file__).resolve().parents[1]
    npz = root / "data" / "processed" / ".test_pkt.npz"
    npz.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        npz,
        flow_keys=np.array(["k1|1|k2|2|TCP", "other"]),
        scores=np.array([0.9, 0.1]),
    )
    s = fn(df, npz)
    assert s is not None
    assert float(s.iloc[0]) == pytest.approx(0.9, rel=0.01)
    assert float(s.iloc[1]) < 0.01
    npz.unlink(missing_ok=True)


def test_run_cascade_with_packet_lstm_column(tmp_path):
    X = pd.DataFrame({"a": [0.0, 1.0]})
    pls = pd.Series([0.0, 0.8], index=X.index)
    ctx = pd.DataFrame({"Timestamp": pd.date_range("2024-01-01", periods=2, freq="min")})
    out = run_cascade(
        X,
        artifacts_dir=tmp_path,
        flow_context=ctx,
        timestamp_col="Timestamp",
        use_rf=False,
        use_embedding=False,
        l2_only_after_l1=False,
        packet_lstm_scores=pls,
    )
    assert "l2_lstm_pkt_score" in out.columns
    assert float(out.iloc[1]["l2_lstm_pkt_score"]) == pytest.approx(0.8)


def test_chunked_detect_smoke(monkeypatch, tmp_path):
    """Без падения при чтении flows.csv по чанкам (минимальный CSV)."""
    csv = tmp_path / "flows.csv"
    csv.write_text(
        "Flow Duration,a,Timestamp,Protocol,Label,Source IP,Destination IP,Source Port,Destination Port,is_attack\n"
        "1.0,0.5,2024/01/01 00:00:00,6,BENIGN,10.0.0.1,10.0.0.2,12345,80,0\n"
        "2.0,0.6,2024/01/01 00:01:00,6,Bot,10.0.0.3,10.0.0.4,443,443,1\n",
        encoding="utf-8",
    )
    parts = []
    for ch in pd.read_csv(csv, chunksize=1):
        parts.append(len(ch))
    assert parts == [1, 1]


def test_run_detection_adds_default_status(monkeypatch, tmp_path):
    mod = _load_03()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "rf_model.joblib").write_text("x", encoding="utf-8")

    def _fake_run_cascade(*_args, **_kwargs):
        return pd.DataFrame(
            [
                {
                    "l1_triggered": True,
                    "l2_rf_attack_score": 0.9,
                    "l2_ae_ratio": 0.0,
                    "l2_lstm_attack_score": 0.0,
                    "l2_emb_attack_score": 0.0,
                    "l2_hdr_cnn_attack_score": 0.0,
                    "l2_lstm_pkt_score": 0.0,
                }
            ]
        )

    def _fake_score_alert(client_ip, network_score, _siem_df):
        return {"ip": client_ip, "threat_score": 77.0, "severity": "High", "recommendation": "test"}

    monkeypatch.setattr("src.pipeline.ensemble_orchestrator.run_cascade", _fake_run_cascade)
    monkeypatch.setattr("src.correlation.threat_scoring.score_alert", _fake_score_alert)

    df = pd.DataFrame([{"a": 1.0, "Source IP": "1.1.1.1"}])
    settings = {
        "paths": {"artifacts": str(artifacts), "siem_events": str(tmp_path / "missing.json")},
        "threat_scoring": {"alert_threshold": 0},
        "aggregation": {"syn_spike_multiplier": 3.0},
    }
    feat_cfg = {"numeric_features": ["a"], "timestamp_column": "Timestamp"}
    alerts = mod.run_detection_on_dataframe(df, settings=settings, feat_cfg=feat_cfg)
    assert len(alerts) == 1
    assert alerts[0]["status"] == "new"


def test_run_detection_warns_on_geo_lookup_error(monkeypatch, tmp_path):
    mod = _load_03()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "rf_model.joblib").write_text("x", encoding="utf-8")

    def _fake_run_cascade(*_args, **_kwargs):
        return pd.DataFrame(
            [
                {
                    "l1_triggered": True,
                    "l2_rf_attack_score": 0.9,
                    "l2_ae_ratio": 0.0,
                    "l2_lstm_attack_score": 0.0,
                    "l2_emb_attack_score": 0.0,
                    "l2_hdr_cnn_attack_score": 0.0,
                    "l2_lstm_pkt_score": 0.0,
                }
            ]
        )

    monkeypatch.setattr("src.pipeline.ensemble_orchestrator.run_cascade", _fake_run_cascade)
    monkeypatch.setattr(
        "src.correlation.geoip_lookup.lookup_lat_lon_for_flow",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("geo db missing")),
    )

    df = pd.DataFrame([{"a": 1.0, "Source IP": "1.1.1.1"}])
    settings = {
        "paths": {"artifacts": str(artifacts), "siem_events": str(tmp_path / "missing.json")},
        "threat_scoring": {"alert_threshold": 0},
        "aggregation": {"syn_spike_multiplier": 3.0},
    }
    feat_cfg = {"numeric_features": ["a"], "timestamp_column": "Timestamp"}
    with pytest.warns(UserWarning, match="GeoIP lookup failed"):
        alerts = mod.run_detection_on_dataframe(df, settings=settings, feat_cfg=feat_cfg)
    assert len(alerts) == 1
