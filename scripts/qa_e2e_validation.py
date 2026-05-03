# =============================================================================
# Independent E2E validation for case 4 readiness.
# =============================================================================
"""Run: python scripts/qa_e2e_validation.py"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def _run(cmd: list[str], cwd: Path) -> dict:
    t0 = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    dt = time.perf_counter() - t0
    return {
        "cmd": " ".join(cmd),
        "rc": int(p.returncode),
        "seconds": round(dt, 3),
        "stdout_tail": "\n".join((p.stdout or "").strip().splitlines()[-5:]),
        "stderr_tail": "\n".join((p.stderr or "").strip().splitlines()[-5:]),
    }


def _dashboard_smoke(py: str, root: Path, port: int = 8798, timeout_s: int = 25) -> dict:
    cmd = [py, "-m", "streamlit", "run", "dashboard/app.py", "--server.headless", "true", "--server.port", str(port)]
    p = subprocess.Popen(
        cmd,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out_lines: list[str] = []
    ok = False
    t0 = time.time()
    try:
        while time.time() - t0 < timeout_s:
            line = p.stdout.readline() if p.stdout else ""
            if line:
                out_lines.append(line.rstrip())
                if "Local URL:" in line:
                    ok = True
                    break
            else:
                time.sleep(0.1)
        return {
            "cmd": " ".join(cmd),
            "started": ok,
            "port": int(port),
            "log_tail": "\n".join(out_lines[-10:]),
        }
    finally:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


def _read_last_jsonl(path: Path) -> dict | None:
    if not path.is_file():
        return None
    lines = [ln for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    if not lines:
        return None
    try:
        return json.loads(lines[-1])
    except Exception:
        return {"raw": lines[-1]}


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    py = sys.executable
    os.environ.setdefault("PYTHONUTF8", "1")

    steps: list[dict] = []
    steps.append(_run([py, "main.py", "generate"], root))
    steps.append(_run([py, "main.py", "prepare", "--input", "data/raw/synthetic_cicids_demo.csv"], root))
    steps.append(_run([py, "main.py", "train", "--skip-torch"], root))
    steps.append(_run([py, "main.py", "train"], root))
    steps.append(_run([py, "main.py", "detect", "--detect-limit", "2000"], root))
    steps.append(_run([py, "main.py", "detect", "--detect-limit", "2000", "--detect-parallel-l2"], root))
    steps.append(
        _run(
            [py, "main.py", "detect", "--detect-limit", "2000", "--detect-stream-chunk-rows", "500", "--detect-log-wall-time"],
            root,
        )
    )
    steps.append(_run([py, "main.py", "online"], root))

    artifacts = root / "artifacts"
    storage = root / "storage"
    artifact_checks = {
        "rf_model": (artifacts / "rf_model.joblib").is_file(),
        "if_model": (artifacts / "if_model.joblib").is_file(),
        "if_agg_model": (artifacts / "if_agg_model.joblib").is_file(),
        "ae_model": (artifacts / "ae_model.pt").is_file(),
        "lstm_model": (artifacts / "lstm_model.pt").is_file(),
        "embedding_classifier": (artifacts / "embedding_classifier.pt").is_file(),
    }

    alerts_ok = False
    alerts_count = 0
    alerts_path = storage / "alerts_latest.json"
    if alerts_path.is_file():
        try:
            alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
            alerts_ok = isinstance(alerts, list)
            alerts_count = len(alerts) if alerts_ok else 0
        except Exception:
            alerts_ok = False

    online_last = _read_last_jsonl(storage / "retrain_history.jsonl")
    dashboard = _dashboard_smoke(py, root, port=8798, timeout_s=25)

    overall_ok = all(s["rc"] == 0 for s in steps) and all(artifact_checks.values()) and alerts_ok and dashboard["started"]
    report = {
        "overall_status": "PASS" if overall_ok else "FAIL",
        "steps": steps,
        "artifact_checks": artifact_checks,
        "alerts_latest": {"path": str(alerts_path), "valid_json_array": alerts_ok, "count": int(alerts_count)},
        "retrain_history_last": online_last,
        "dashboard_smoke": dashboard,
    }

    out_path = storage / "qa_e2e_validation.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Saved E2E report: {out_path}")


if __name__ == "__main__":
    main()
