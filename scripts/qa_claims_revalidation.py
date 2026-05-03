# =============================================================================
# Independent re-validation of key bug claims BUG-001..BUG-004.
# =============================================================================
"""Run: python scripts/qa_claims_revalidation.py"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pandas as pd
import yaml


def _run(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> dict:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=env)
    return {
        "cmd": " ".join(cmd),
        "rc": int(p.returncode),
        "stdout": p.stdout[-4000:],
        "stderr": p.stderr[-4000:],
    }


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    py = sys.executable
    out: dict[str, dict] = {}

    # Ensure demo raw exists for tiny/utf16 checks.
    _run([py, "main.py", "generate"], root)
    raw_demo = root / "data" / "raw" / "synthetic_cicids_demo.csv"
    flows = root / "data" / "processed" / "flows.csv"

    # BUG-001: help on Windows should not crash with UnicodeEncodeError.
    r1 = _run([py, "scripts/03_run_detection_batch.py", "--help"], root)
    s1 = (
        r1["rc"] == 0
        and "usage:" in r1["stdout"].lower()
        and "unicodeencodeerror" not in (r1["stdout"] + r1["stderr"]).lower()
    )
    out["BUG-001"] = {"status": "CONFIRMED" if s1 else "REJECTED", "evidence": r1}

    # BUG-002: UTF-16 input should fail explicitly and not corrupt flows.csv.
    utf16_path = root / "data" / "raw" / "qa_bug002_utf16.csv"
    df_demo = pd.read_csv(raw_demo, encoding="utf-8", encoding_errors="replace", low_memory=False)
    df_demo.head(50).to_csv(utf16_path, index=False, encoding="utf-16")
    before_hash = _sha256(flows)
    r2 = _run([py, "main.py", "prepare", "--input", str(utf16_path)], root)
    after_hash = _sha256(flows)
    msg2 = (r2["stdout"] + r2["stderr"]).lower()
    s2 = (r2["rc"] != 0) and ("utf-8" in msg2 or "utf8" in msg2) and (before_hash == after_hash)
    out["BUG-002"] = {
        "status": "CONFIRMED" if s2 else "REJECTED",
        "evidence": {
            **r2,
            "flows_hash_before": before_hash,
            "flows_hash_after": after_hash,
        },
    }

    # BUG-003: tiny dataset train should fail controlled (clear message, no raw traceback dump).
    tiny_csv = root / "data" / "raw" / "qa_bug003_tiny.csv"
    df_demo.head(1).to_csv(tiny_csv, index=False, encoding="utf-8")
    flows_backup = flows.read_bytes() if flows.is_file() else None
    r3_prepare = _run([py, "main.py", "prepare", "--input", str(tiny_csv)], root)
    r3_train = _run([py, "main.py", "train", "--skip-torch"], root)
    # Restore previous flows to avoid side effects.
    if flows_backup is not None:
        flows.parent.mkdir(parents=True, exist_ok=True)
        flows.write_bytes(flows_backup)
    blob3 = (r3_train["stdout"] + r3_train["stderr"]).lower()
    s3 = (
        r3_prepare["rc"] == 0
        and r3_train["rc"] != 0
        and ("insufficient" in blob3 or "недостат" in blob3 or "at least" in blob3)
        and "traceback (most recent call last)" not in blob3
    )
    out["BUG-003"] = {
        "status": "CONFIRMED" if s3 else "REJECTED",
        "evidence": {"prepare": r3_prepare, "train": r3_train},
    }

    # BUG-004: online.retrain_interval_minutes validation.
    with tempfile.TemporaryDirectory(prefix="ids_bug004_") as td:
        troot = Path(td)
        (troot / "config").mkdir(parents=True, exist_ok=True)
        cfg = yaml.safe_load((root / "config" / "settings.yaml").read_text(encoding="utf-8")) or {}
        cfg.setdefault("online", {})
        cfg["online"]["retrain_interval_minutes"] = "bad-value"
        (troot / "config" / "settings.yaml").write_text(
            yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["IDS_PROJECT_ROOT"] = str(troot)
        r4 = _run([py, "scripts/04_run_online_loop.py"], root, env=env)
    b4 = (r4["stdout"] + r4["stderr"]).lower()
    s4 = (r4["rc"] != 0) and ("retrain_interval_minutes" in b4) and ("некоррект" in b4 or "invalid" in b4)
    out["BUG-004"] = {"status": "CONFIRMED" if s4 else "REJECTED", "evidence": r4}

    # Sanity cleanup.
    for p in (utf16_path, tiny_csv):
        try:
            p.unlink()
        except OSError:
            pass

    summary = {
        "confirmed": sum(1 for k in out.values() if k["status"] == "CONFIRMED"),
        "rejected": sum(1 for k in out.values() if k["status"] == "REJECTED"),
    }
    report = {"summary": summary, "bugs": out}
    out_path = root / "storage" / "qa_claims_revalidation.json"
    out_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"Saved claims report: {out_path}")


if __name__ == "__main__":
    main()
