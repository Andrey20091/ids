from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pandas as pd


def _run_prepare(root: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(root / "scripts" / "01_prepare_data.py"), *args],
        cwd=root,
        capture_output=True,
        text=True,
    )


def test_prepare_append_output_appends_without_duplicate_header(tmp_path):
    root = Path(__file__).resolve().parents[1]
    raw = tmp_path / "raw.csv"
    out = tmp_path / "flows.csv"
    pd.DataFrame(
        {
            "Timestamp": ["2024-01-01 00:00:00", "2024-01-01 00:01:00"],
            "Source IP": ["1.1.1.1", "1.1.1.2"],
            "Destination IP": ["2.2.2.2", "2.2.2.3"],
            "Destination Port": [80, 443],
            "Protocol": [6, 6],
            "Label": ["BENIGN", "Bot"],
            "Flow Duration": [1.0, 2.0],
        }
    ).to_csv(raw, index=False)

    r1 = _run_prepare(root, ["--input", str(raw), "--output", str(out)])
    assert r1.returncode == 0, r1.stderr + r1.stdout
    r2 = _run_prepare(root, ["--input", str(raw), "--output", str(out), "--append-output"])
    assert r2.returncode == 0, r2.stderr + r2.stdout

    text = out.read_text(encoding="utf-8")
    # Header must exist once only.
    assert text.count("is_attack") == 1
    df = pd.read_csv(out)
    assert len(df) == 4


def test_prepare_append_output_schema_mismatch_fails(tmp_path):
    root = Path(__file__).resolve().parents[1]
    raw = tmp_path / "raw.csv"
    out = tmp_path / "flows.csv"
    pd.DataFrame(
        {
            "Timestamp": ["2024-01-01 00:00:00"],
            "Source IP": ["1.1.1.1"],
            "Destination IP": ["2.2.2.2"],
            "Destination Port": [80],
            "Protocol": [6],
            "Label": ["BENIGN"],
            "Flow Duration": [1.0],
        }
    ).to_csv(raw, index=False)

    r1 = _run_prepare(root, ["--input", str(raw), "--output", str(out)])
    assert r1.returncode == 0, r1.stderr + r1.stdout

    # Corrupt schema of existing output before append.
    out.write_text("foo,bar\n1,2\n", encoding="utf-8")
    r2 = _run_prepare(root, ["--input", str(raw), "--output", str(out), "--append-output"])
    assert r2.returncode != 0
    assert "schema mismatch" in (r2.stderr + r2.stdout).lower()
