# =============================================================================
# Скрипт 08: синхронизация alerts_latest.json -> storage/incidents.jsonl
# =============================================================================
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.governance.storage import stable_alert_hash, upsert_jsonl, utc_now_iso


def _incident_from_alert(alert: dict, idx: int) -> dict:
    now = utc_now_iso()
    ref_hash = stable_alert_hash(alert)
    ip = str(alert.get("ip", "0.0.0.0"))
    ts = str(alert.get("ts", "") or "")
    threat = float(alert.get("threat_score", 0.0) or 0.0)
    incident_id = f"inc_{ref_hash[:12]}"
    return {
        "incident_id": incident_id,
        "created_at": now,
        "updated_at": now,
        "status": "new",
        "priority": "high" if threat >= 80 else ("medium" if threat >= 55 else "low"),
        "ip": ip,
        "ts": ts,
        "threat_score": threat,
        "recommendation": str(alert.get("recommendation", "")),
        "signal": {
            "l1_triggered": bool(alert.get("l1_triggered", False)),
            "l2_rf_attack_score": float(alert.get("l2_rf_attack_score", 0.0) or 0.0),
            "l2_ae_ratio": float(alert.get("l2_ae_ratio", 0.0) or 0.0),
            "l2_lstm_attack_score": float(alert.get("l2_lstm_attack_score", 0.0) or 0.0),
            "l2_emb_attack_score": float(alert.get("l2_emb_attack_score", 0.0) or 0.0),
        },
        "siem": {
            "failed_login": int(alert.get("siem_failed_login", 0) or 0),
            "config_change": int(alert.get("siem_config_change", 0) or 0),
        },
        "owner": None,
        "tags": ["detect_batch"],
        "linked_alert_hash": ref_hash,
        "alert_seq": idx,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync alerts_latest.json into incidents.jsonl")
    parser.add_argument("--alerts", type=str, default=str(_ROOT / "storage/alerts_latest.json"))
    parser.add_argument("--incidents", type=str, default=str(_ROOT / "storage/incidents.jsonl"))
    args = parser.parse_args()

    alerts_path = Path(args.alerts)
    if not alerts_path.is_absolute():
        alerts_path = _ROOT / alerts_path
    incidents_path = Path(args.incidents)
    if not incidents_path.is_absolute():
        incidents_path = _ROOT / incidents_path

    if not alerts_path.is_file():
        raise SystemExit(f"Alerts file not found: {alerts_path}")
    with open(alerts_path, encoding="utf-8") as f:
        payload = json.load(f)
    if not isinstance(payload, list):
        raise SystemExit("alerts_latest.json must be a JSON list")

    rows = [_incident_from_alert(a if isinstance(a, dict) else {}, i) for i, a in enumerate(payload)]
    ins, upd = upsert_jsonl(incidents_path, rows, key="incident_id")
    print(f"Synced incidents: inserted={ins}, updated={upd}, total_incoming={len(rows)}")


if __name__ == "__main__":
    main()

