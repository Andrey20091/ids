import json

from dashboard.data_connector import (
    build_incident_report_row,
    dashboard_filter_metadata,
    load_alerts_json,
    load_retrain_history,
    load_sandbox_reports,
)


def test_load_alerts_json_empty_or_invalid_returns_empty(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    assert load_alerts_json(empty).empty
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert load_alerts_json(bad).empty
    obj = tmp_path / "obj.json"
    obj.write_text('{"x":1}', encoding="utf-8")
    assert load_alerts_json(obj).empty


def test_load_alerts_json_merges_incident_status(tmp_path):
    alerts = [{"ip": "1.1.1.1", "ts": "2026-01-01 00:00:00", "threat_score": 88.0, "recommendation": "x"}]
    (tmp_path / "alerts_latest.json").write_text(json.dumps(alerts), encoding="utf-8")
    inc = {
        "incident_id": "inc_1",
        "ip": "1.1.1.1",
        "ts": "2026-01-01 00:00:00",
        "threat_score": 88.0,
        "status": "triaged",
        "owner": "analyst",
    }
    (tmp_path / "incidents.jsonl").write_text(json.dumps(inc, ensure_ascii=False) + "\n", encoding="utf-8")
    df = load_alerts_json(tmp_path / "alerts_latest.json")
    assert len(df) == 1
    assert df.iloc[0]["status"] == "triaged"


def test_retrain_and_sandbox_loaders(tmp_path):
    (tmp_path / "retrain_history.jsonl").write_text(
        json.dumps({"ts": "2026-01-01T00:00:00Z", "result": "ok", "if_baseline_f1": 0.2}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "sandbox_reports.jsonl").write_text(
        json.dumps({"created_at": "2026-01-01T01:00:00Z", "metrics": {"delta_f1": 0.03}, "decision": "ready_for_approval"}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    h = load_retrain_history(tmp_path / "retrain_history.jsonl")
    s = load_sandbox_reports(tmp_path / "sandbox_reports.jsonl")
    assert "ts_parsed" in h.columns
    assert "delta_f1" in s.columns


def test_build_incident_report_row():
    row = build_incident_report_row(
        {
            "incident_id": "inc_1",
            "signal": {"l1_triggered": True, "l2_rf_attack_score": 0.8},
            "siem": {"failed_login": 2, "config_change": 1},
        }
    )
    assert row["incident_id"] == "inc_1"
    assert row["l1_triggered"] is True
    assert row["siem_failed_login"] == 2


def test_load_alerts_json_adds_default_status_when_missing(tmp_path):
    alerts = [{"ip": "1.1.1.1", "threat_score": 42.0}]
    p = tmp_path / "alerts_latest.json"
    p.write_text(json.dumps(alerts), encoding="utf-8")
    df = load_alerts_json(p)
    assert "status" in df.columns
    assert set(df["status"].astype(str)) == {"new"}
    assert bool(df["_status_defaulted"].all())


def test_dashboard_filter_metadata_single_severity_note():
    df = load_alerts_json_data(
        [
            {"ip": "1.1.1.1", "threat_score": 55.0, "severity": "Medium", "status": "new"},
            {"ip": "2.2.2.2", "threat_score": 58.0, "severity": "Medium", "status": "triaged"},
        ]
    )
    meta = dashboard_filter_metadata(df)
    assert meta["severity_options"] == ["Medium"]
    assert "только один уровень severity" in meta["single_severity_note"]
    assert meta["status_options"] == ["new", "triaged"]


def test_dashboard_filter_metadata_multi_values():
    df = load_alerts_json_data(
        [
            {"ip": "1.1.1.1", "threat_score": 20.0, "severity": "Low", "status": "new"},
            {"ip": "2.2.2.2", "threat_score": 70.0, "severity": "High", "status": "triaged"},
            {"ip": "3.3.3.3", "threat_score": 90.0, "severity": "Emergency", "status": "closed_true"},
        ]
    )
    meta = dashboard_filter_metadata(df)
    assert meta["severity_options"] == ["Low", "High", "Emergency"]
    assert meta["single_severity_note"] == ""
    assert meta["status_options"] == ["closed_true", "new", "triaged"]


def load_alerts_json_data(alerts: list[dict]):
    """Helper: keep tests focused on connector behavior."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "alerts_latest.json"
        p.write_text(json.dumps(alerts), encoding="utf-8")
        return load_alerts_json(p)

