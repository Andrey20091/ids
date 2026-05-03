from __future__ import annotations

import importlib.util
from pathlib import Path

import pandas as pd


def _load_detect_script():
    root = Path(__file__).resolve().parents[1]
    path = root / "scripts" / "03_run_detection_batch.py"
    spec = importlib.util.spec_from_file_location("detect_script_rules_mod", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_proxy_rule_signals_hits_expected_rules():
    mod = _load_detect_script()
    row = pd.Series(
        {
            "Flow Packets/s": 500,
            "Flow Bytes/s": 400000,
            "SYN Flag Count": 1,
            "RST Flag Count": 1,
            "Destination Port": 22,
            "http_request_uri": "https://x.local/admin",
        }
    )
    rules, boost = mod._proxy_rule_signals(row)
    assert "high_packet_rate" in rules
    assert "high_byte_rate" in rules
    assert "syn_rst_combo" in rules
    assert "unusual_destination_port" in rules
    assert "suspicious_uri_pattern" in rules
    assert boost > 0.0


def test_proxy_rule_signals_benign_rates_silent():
    mod = _load_detect_script()
    row = pd.Series(
        {
            "Flow Packets/s": 120,
            "Flow Bytes/s": 80000,
            "SYN Flag Count": 0,
            "RST Flag Count": 0,
            "Destination Port": 443,
            "http_request_uri": "https://example.com/home",
        }
    )
    rules, boost = mod._proxy_rule_signals(row)
    assert rules == []
    assert boost == 0.0


def test_proxy_rule_signals_prepared_export_fwd_bwd_pps_fallback():
    """Prepared flows.csv often omits Flow Packets/s; Fwd+Bwd Packets/s carry the same intent."""
    mod = _load_detect_script()
    row = pd.Series(
        {
            "Fwd Packets/s": 250.0,
            "Bwd Packets/s": 260.0,
            "Destination Port": 443,
            "http_request_uri": "",
        }
    )
    rules, boost = mod._proxy_rule_signals(row)
    assert "high_packet_rate" in rules
    assert boost > 0.0


def test_run_detection_disable_proxy_rules_clears_triggered(monkeypatch, tmp_path):
    mod = _load_detect_script()
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
        "src.correlation.threat_scoring.score_alert",
        lambda ip, *_a, **_k: {"ip": ip, "threat_score": 77.0, "severity": "High", "recommendation": "t"},
    )

    df = pd.DataFrame(
        [
            {
                "a": 1.0,
                "Source IP": "1.1.1.1",
                "Timestamp": "2024/01/01 00:00:00",
                "Flow Packets/s": 500.0,
                "Flow Bytes/s": 400000.0,
                "SYN Flag Count": 1.0,
                "RST Flag Count": 1.0,
                "Destination Port": 22.0,
                "http_request_uri": "https://x/admin",
            }
        ]
    )
    settings = {
        "paths": {"artifacts": str(artifacts), "siem_events": str(tmp_path / "missing.json")},
        "threat_scoring": {"alert_threshold": 0},
        "aggregation": {"syn_spike_multiplier": 3.0},
    }
    feat_cfg = {"numeric_features": ["a"], "timestamp_column": "Timestamp"}
    on = mod.run_detection_on_dataframe(
        df, settings=settings, feat_cfg=feat_cfg, enable_proxy_rules=True
    )
    off = mod.run_detection_on_dataframe(
        df, settings=settings, feat_cfg=feat_cfg, enable_proxy_rules=False
    )
    assert on and on[0].get("triggered_rules")
    assert off and off[0].get("triggered_rules") == []


def test_run_detection_dedup_same_ip_severity(monkeypatch, tmp_path):
    mod = _load_detect_script()
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
                },
                {
                    "l1_triggered": True,
                    "l2_rf_attack_score": 0.9,
                    "l2_ae_ratio": 0.0,
                    "l2_lstm_attack_score": 0.0,
                    "l2_emb_attack_score": 0.0,
                    "l2_hdr_cnn_attack_score": 0.0,
                    "l2_lstm_pkt_score": 0.0,
                },
            ]
        )

    monkeypatch.setattr("src.pipeline.ensemble_orchestrator.run_cascade", _fake_run_cascade)
    monkeypatch.setattr(
        "src.correlation.threat_scoring.score_alert",
        lambda ip, *_a, **_k: {"ip": ip, "threat_score": 77.0, "severity": "High", "recommendation": "t"},
    )

    df = pd.DataFrame(
        [
            {
                "a": 1.0,
                "Source IP": "9.9.9.9",
                "Timestamp": "2024/01/01 00:00:00",
                "Flow Packets/s": 0.0,
                "Flow Bytes/s": 0.0,
                "SYN Flag Count": 0.0,
                "RST Flag Count": 0.0,
                "Destination Port": 443.0,
                "http_request_uri": "https://x/",
            },
            {
                "a": 1.0,
                "Source IP": "9.9.9.9",
                "Timestamp": "2024/01/01 00:00:05",
                "Flow Packets/s": 0.0,
                "Flow Bytes/s": 0.0,
                "SYN Flag Count": 0.0,
                "RST Flag Count": 0.0,
                "Destination Port": 443.0,
                "http_request_uri": "https://x/",
            },
        ]
    )
    settings = {
        "paths": {"artifacts": str(artifacts), "siem_events": str(tmp_path / "missing.json")},
        "threat_scoring": {"alert_threshold": 0},
        "aggregation": {"syn_spike_multiplier": 3.0},
    }
    feat_cfg = {"numeric_features": ["a"], "timestamp_column": "Timestamp"}
    alerts = mod.run_detection_on_dataframe(
        df,
        settings=settings,
        feat_cfg=feat_cfg,
        dedup_window_seconds=3600,
    )
    assert len(alerts) == 1
