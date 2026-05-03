import os
import subprocess
import sys
from pathlib import Path


def test_online_loop_missing_online_key_fails_with_clear_message(tmp_path):
    root = Path(__file__).resolve().parents[1]
    (tmp_path / "config").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "processed").mkdir(parents=True, exist_ok=True)
    (tmp_path / "config" / "settings.yaml").write_text(
        "paths:\n  artifacts: artifacts\n  storage: storage\n",
        encoding="utf-8",
    )
    (tmp_path / "data" / "processed" / "flows.csv").write_text(
        "Flow Duration,is_attack\n1.0,0\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["IDS_PROJECT_ROOT"] = str(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(root / "scripts" / "04_run_online_loop.py")],
        cwd=root,
        capture_output=True,
        text=True,
        env=env,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "online.retrain_interval_minutes" in out
