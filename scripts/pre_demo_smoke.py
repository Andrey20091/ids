# =============================================================================
# One-click pre-demo smoke orchestrator (quick/full).
# =============================================================================
"""Run: python scripts/pre_demo_smoke.py [--with-soak] [--with-perf]"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path


def _run(cmd: list[str], cwd: Path) -> dict:
    t0 = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return {
        "cmd": " ".join(cmd),
        "rc": int(p.returncode),
        "seconds": round(time.perf_counter() - t0, 3),
        "stdout_tail": "\n".join((p.stdout or "").strip().splitlines()[-8:]),
        "stderr_tail": "\n".join((p.stderr or "").strip().splitlines()[-8:]),
    }


def _load_json(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--with-soak", action="store_true", help="Include SIEM soak (longer)")
    ap.add_argument("--with-perf", action="store_true", help="Include perf baseline (long)")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1]
    py = sys.executable
    steps: list[dict] = []

    steps.append(_run([py, "-c", "import sklearn, torch, streamlit, pandas, yaml; print('deps_ok')"], root))
    steps.append(_run([py, "scripts/qa_claims_revalidation.py"], root))
    steps.append(_run([py, "scripts/qa_e2e_validation.py"], root))
    steps.append(_run([py, "scripts/qa_dashboard_ux_protocol.py"], root))
    steps.append(_run([py, "-m", "pytest", "tests", "-q", "--tb=short"], root))

    if args.with_soak:
        steps.append(_run([py, "scripts/qa_siem_http_soak.py", "--iterations", "120", "--timeout", "1", "--detect-every", "10"], root))
    if args.with_perf:
        steps.append(
            _run(
                [
                    py,
                    "scripts/qa_perf_baseline.py",
                    "--repeat-factor",
                    "20",
                    "--detect-limit",
                    "50000",
                    "--chunk-rows",
                    "5000",
                    "--include-torch",
                ],
                root,
            )
        )

    claims = _load_json(root / "storage" / "qa_claims_revalidation.json") or {}
    e2e = _load_json(root / "storage" / "qa_e2e_validation.json") or {}
    ux = _load_json(root / "storage" / "qa_dashboard_ux_protocol.json") or {}
    soak = _load_json(root / "storage" / "qa_siem_http_soak_report.json") if args.with_soak else None
    perf = _load_json(root / "storage" / "qa_perf_baseline_report.json") if args.with_perf else None

    ok_steps = all(s["rc"] == 0 for s in steps)
    ok_claims = claims.get("summary", {}).get("rejected", 1) == 0
    ok_e2e = e2e.get("overall_status") == "PASS"
    ok_ux = ux.get("summary", {}).get("checks_failed", 1) == 0
    ok_soak = (not args.with_soak) or (
        soak and soak.get("loader_exceptions") == 0 and soak.get("detect_exceptions") == 0
    )
    ok_perf = (not args.with_perf) or (perf and all(int(r.get("rc", 1)) == 0 for r in perf.get("runs", [])))

    overall = ok_steps and ok_claims and ok_e2e and ok_ux and ok_soak and ok_perf
    report = {
        "mode": {
            "with_soak": bool(args.with_soak),
            "with_perf": bool(args.with_perf),
        },
        "overall_status": "PASS" if overall else "FAIL",
        "gates": {
            "all_steps_rc_zero": ok_steps,
            "claims_revalidation": ok_claims,
            "e2e_validation": ok_e2e,
            "dashboard_ux_protocol": ok_ux,
            "siem_soak": bool(ok_soak),
            "perf_baseline": bool(ok_perf),
        },
        "steps": steps,
        "artifacts": {
            "claims": "storage/qa_claims_revalidation.json",
            "e2e": "storage/qa_e2e_validation.json",
            "ux": "storage/qa_dashboard_ux_protocol.json",
            "soak": "storage/qa_siem_http_soak_report.json" if args.with_soak else None,
            "perf": "storage/qa_perf_baseline_report.json" if args.with_perf else None,
        },
    }

    out_path = root / "storage" / "pre_demo_smoke_report.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Saved pre-demo report: {out_path}")


if __name__ == "__main__":
    main()
