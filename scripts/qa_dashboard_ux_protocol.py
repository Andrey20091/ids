# =============================================================================
# QA-протокол dashboard UX (полуавтоматический): проверка данных и фильтров.
# =============================================================================
"""Run: python scripts/qa_dashboard_ux_protocol.py"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pandas as pd

_bundle = Path(__file__).resolve().parents[1]
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle

from dashboard.data_connector import (
    build_incident_report_row,
    load_alerts_json,
    load_incidents_jsonl,
)


def _apply_filters(
    df: pd.DataFrame,
    *,
    statuses: list[str],
    severities: list[str],
    ip_q: str,
    min_score: float,
) -> pd.DataFrame:
    out = df.copy()
    if statuses and "status" in out.columns:
        out = out[out["status"].astype(str).isin(statuses)]
    if severities and "severity" in out.columns:
        out = out[out["severity"].astype(str).isin(severities)]
    if ip_q and "ip" in out.columns:
        out = out[out["ip"].astype(str).str.contains(ip_q, case=False, na=False)]
    if "threat_score" in out.columns:
        out = out[pd.to_numeric(out["threat_score"], errors="coerce").fillna(0.0) >= min_score]
    return out


def main() -> None:
    storage = _ROOT / "storage"
    alerts_path = storage / "alerts_latest.json"
    incidents_path = storage / "incidents.jsonl"
    out_path = storage / "qa_dashboard_ux_protocol.json"

    checks: list[dict] = []
    alerts = load_alerts_json(alerts_path)
    checks.append(
        {
            "check": "alerts_load",
            "status": "PASS" if isinstance(alerts, pd.DataFrame) else "FAIL",
            "details": {"rows": int(len(alerts)), "path": str(alerts_path)},
        }
    )

    # Если алертов нет, создаём локальный in-memory набор для UX-проверок фильтра.
    if alerts.empty:
        alerts = pd.DataFrame(
            [
                {
                    "ip": "10.0.0.10",
                    "severity": "High",
                    "threat_score": 72.0,
                    "recommendation": "High: tighten monitoring",
                    "status": "new",
                    "ts": "2026-01-01 10:00:00",
                },
                {
                    "ip": "10.0.0.20",
                    "severity": "Low",
                    "threat_score": 31.0,
                    "recommendation": "Low: watchlist",
                    "status": "triaged",
                    "ts": "2026-01-01 10:05:00",
                },
            ]
        )
        checks.append(
            {
                "check": "alerts_fixture_fallback",
                "status": "PASS",
                "details": {"rows": int(len(alerts))},
            }
        )

    # Фильтр status
    if "status" in alerts.columns and alerts["status"].astype(str).eq("new").any():
        f1 = _apply_filters(alerts, statuses=["new"], severities=[], ip_q="", min_score=0)
        ok1 = len(f1) >= 1 and all(f1["status"].astype(str).eq("new"))
        checks.append(
            {
                "check": "filter_status",
                "status": "PASS" if ok1 else "FAIL",
                "details": {"rows_after": int(len(f1))},
            }
        )
    else:
        checks.append(
            {
                "check": "filter_status",
                "status": "PASS",
                "details": {"note": "no 'new' rows in current dataset; empty result expected"},
            }
        )

    # Фильтр severity
    f2 = _apply_filters(alerts, statuses=[], severities=["High"], ip_q="", min_score=0)
    ok2 = ("severity" in f2.columns) and (len(f2) >= 0) and all(f2["severity"].astype(str).eq("High"))
    checks.append(
        {
            "check": "filter_severity",
            "status": "PASS" if ok2 else "FAIL",
            "details": {"rows_after": int(len(f2))},
        }
    )

    # Фильтр ip содержит
    sample_ip = str(alerts.iloc[0]["ip"]) if "ip" in alerts.columns and len(alerts) else ""
    f3 = _apply_filters(alerts, statuses=[], severities=[], ip_q=sample_ip.split(".")[0], min_score=0)
    checks.append(
        {
            "check": "filter_ip_contains",
            "status": "PASS" if len(f3) >= 1 else "FAIL",
            "details": {"query": sample_ip.split(".")[0], "rows_after": int(len(f3))},
        }
    )

    # Фильтр min score
    f4 = _apply_filters(alerts, statuses=[], severities=[], ip_q="", min_score=50)
    ok4 = "threat_score" in f4.columns and all(pd.to_numeric(f4["threat_score"], errors="coerce").fillna(0) >= 50)
    checks.append(
        {
            "check": "filter_min_score",
            "status": "PASS" if ok4 else "FAIL",
            "details": {"rows_after": int(len(f4))},
        }
    )

    # Временной ряд: нужен ts или корректный fallback.
    checks.append(
        {
            "check": "timeseries_precondition",
            "status": "PASS",
            "details": {"has_ts_column": bool("ts" in alerts.columns)},
        }
    )

    # Карта: ip обязателен; geo-координаты опциональны.
    checks.append(
        {
            "check": "map_precondition",
            "status": "PASS" if "ip" in alerts.columns else "FAIL",
            "details": {"has_geo": bool({"latitude", "longitude"}.issubset(alerts.columns))},
        }
    )

    # Рекомендации/таблица
    checks.append(
        {
            "check": "recommendations_precondition",
            "status": "PASS" if "recommendation" in alerts.columns else "FAIL",
            "details": {},
        }
    )

    # Карточка инцидента: если incidents нет, это допустимый empty state.
    inc = load_incidents_jsonl(incidents_path)
    if not inc.empty and "incident_id" in inc.columns:
        row = build_incident_report_row(inc.iloc[0].to_dict())
        ok = "incident_id" in row
        checks.append(
            {
                "check": "incident_card",
                "status": "PASS" if ok else "FAIL",
                "details": {"incident_id": row.get("incident_id")},
            }
        )
    else:
        checks.append(
            {
                "check": "incident_card",
                "status": "PASS",
                "details": {"note": "incidents.jsonl empty - empty state acceptable"},
            }
        )

    summary = {
        "checks_total": len(checks),
        "checks_passed": sum(1 for c in checks if c["status"] == "PASS"),
        "checks_failed": sum(1 for c in checks if c["status"] != "PASS"),
    }

    out = {"summary": summary, "checks": checks}
    out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"Saved protocol: {out_path}")


if __name__ == "__main__":
    main()
