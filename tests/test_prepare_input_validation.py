import subprocess
import sys
from pathlib import Path

import pandas as pd


def _run_prepare(path: Path, extra_args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "01_prepare_data.py"
    argv = [sys.executable, str(script), "--input", str(path)]
    if extra_args:
        argv.extend(extra_args)
    return subprocess.run(
        argv,
        cwd=root,
        capture_output=True,
        text=True,
    )


def test_prepare_empty_csv_returns_clear_error(tmp_path: Path):
    p = tmp_path / "empty.csv"
    p.write_text("", encoding="utf-8")
    proc = _run_prepare(p)
    assert proc.returncode != 0
    assert "CSV пустой" in (proc.stdout + proc.stderr)


def test_prepare_utf16_csv_returns_encoding_error(tmp_path: Path):
    p = tmp_path / "utf16.csv"
    pd.DataFrame(
        [
            {
                "Flow ID": 1,
                "Source IP": "1.1.1.1",
                "Destination IP": "2.2.2.2",
                "Protocol": 6,
                "Timestamp": "21/01/2025 08:00:00",
                "Label": "BENIGN",
            }
        ]
    ).to_csv(p, index=False, encoding="utf-16")
    proc = _run_prepare(p)
    assert proc.returncode != 0
    assert "UTF-8" in (proc.stdout + proc.stderr)


def test_prepare_missing_critical_columns_fails_by_default(tmp_path: Path):
    p = tmp_path / "missing.csv"
    pd.DataFrame([{"Flow Duration": 1.0}]).to_csv(p, index=False, encoding="utf-8")
    proc = _run_prepare(p)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "Критичные входные колонки отсутствуют" in out
    assert "--allow-missing-columns" in out


def test_prepare_missing_critical_columns_can_run_in_compat_mode(tmp_path: Path):
    p = tmp_path / "missing.csv"
    out_csv = tmp_path / "flows_out.csv"
    pd.DataFrame([{"Flow Duration": 1.0}]).to_csv(p, index=False, encoding="utf-8")
    proc = _run_prepare(p, ["--allow-missing-columns", "--output", str(out_csv)])
    assert proc.returncode == 0
    assert out_csv.is_file()
