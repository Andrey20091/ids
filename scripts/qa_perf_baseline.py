# =============================================================================
# QA baseline: prepare/train/detect wall-clock на увеличенном synthetic dataset.
# =============================================================================
"""Run: python scripts/qa_perf_baseline.py --repeat-factor 20 --include-torch"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd


def _run(cmd: list[str], cwd: Path) -> dict:
    t0 = time.perf_counter()
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    dt = time.perf_counter() - t0
    return {
        "cmd": " ".join(cmd),
        "rc": int(p.returncode),
        "seconds": round(dt, 3),
        "stdout_tail": "\n".join((p.stdout or "").strip().splitlines()[-3:]),
        "stderr_tail": "\n".join((p.stderr or "").strip().splitlines()[-3:]),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat-factor", type=int, default=20)
    ap.add_argument("--detect-limit", type=int, default=50000)
    ap.add_argument("--chunk-rows", type=int, default=5000)
    ap.add_argument("--include-torch", action="store_true")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1]
    py = str(root / ".venv" / "Scripts" / "python.exe")

    # База: synthetic.csv (если нет — генерим).
    base_raw = root / "data" / "raw" / "synthetic_cicids_demo.csv"
    if not base_raw.is_file():
        _ = _run([py, "main.py", "generate"], root)
    base_df = pd.read_csv(base_raw, encoding="utf-8", encoding_errors="replace", low_memory=False)
    large_df = pd.concat([base_df] * max(1, int(args.repeat_factor)), ignore_index=True)
    large_raw = root / "data" / "raw" / "qa_perf_large.csv"
    large_raw.parent.mkdir(parents=True, exist_ok=True)
    large_df.to_csv(large_raw, index=False)

    rows_large = int(len(large_df))
    report: dict = {
        "dataset_context": {
            "base_rows": int(len(base_df)),
            "repeat_factor": int(args.repeat_factor),
            "large_rows": rows_large,
            "raw_file": str(large_raw),
            "note": "RAM/CPU telemetry unavailable (psutil not installed); wall-clock only.",
        },
        "runs": [],
    }

    runs = report["runs"]
    runs.append(_run([py, "main.py", "prepare", "--input", str(large_raw)], root))
    runs.append(_run([py, "main.py", "train", "--skip-torch"], root))
    runs.append(
        _run(
            [py, "main.py", "detect", "--detect-limit", str(args.detect_limit)],
            root,
        )
    )
    runs.append(
        _run(
            [py, "main.py", "detect", "--detect-limit", str(args.detect_limit), "--detect-parallel-l2"],
            root,
        )
    )
    runs.append(
        _run(
            [
                py,
                "main.py",
                "detect",
                "--detect-limit",
                str(args.detect_limit),
                "--detect-stream-chunk-rows",
                str(args.chunk_rows),
                "--detect-log-wall-time",
            ],
            root,
        )
    )

    if args.include_torch:
        # Для torch-пути берём усечённый набор (иначе может быть слишком долго для QA-итерации).
        med_rows = min(rows_large, 20000)
        med_df = large_df.head(med_rows).copy()
        med_raw = root / "data" / "raw" / "qa_perf_medium_torch.csv"
        med_df.to_csv(med_raw, index=False)
        runs.append(_run([py, "main.py", "prepare", "--input", str(med_raw)], root))
        runs.append(_run([py, "main.py", "train"], root))
        report["dataset_context"]["medium_torch_rows"] = int(med_rows)

    out = root / "storage" / "qa_perf_baseline_report.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Saved perf report: {out}")


if __name__ == "__main__":
    main()
