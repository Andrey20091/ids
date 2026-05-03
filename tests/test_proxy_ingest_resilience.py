from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


def _run_ingest(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "scripts/07_ingest_proxy_ndjson.py", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def test_proxy_ingest_skips_malformed_and_missing_required(tmp_path: Path):
    ndjson = tmp_path / "proxy.ndjson"
    out_csv = tmp_path / "proxy.csv"
    lines = [
        '{"ts": 1, "client_ip": "127.0.0.1", "host": "ok.local", "duration_ms": 10, "bytes_up": 10, "bytes_down": 5, "port": 443, "status": 200}',
        '{"ts": 2, "client_ip": "127.0.0.1", "duration_ms": 10}',  # missing host
        "{bad json line}",
        "",
    ]
    ndjson.write_text("\n".join(lines), encoding="utf-8")

    run = _run_ingest("--ndjson", str(ndjson), "--csv-out", str(out_csv))
    assert run.returncode == 0, run.stderr + run.stdout
    assert "invalid_json=1" in run.stdout
    assert "missing_required=1" in run.stdout
    df = pd.read_csv(out_csv)
    assert len(df) == 1


def test_proxy_ingest_incremental_checkpoint_processes_only_new(tmp_path: Path):
    ndjson = tmp_path / "proxy.ndjson"
    out_csv = tmp_path / "proxy.csv"
    state = tmp_path / "proxy_state.json"

    first = '{"ts": 1, "client_ip": "127.0.0.1", "host": "a.local", "duration_ms": 10, "bytes_up": 10, "bytes_down": 5, "port": 443, "status": 200}'
    second = '{"ts": 2, "client_ip": "127.0.0.1", "host": "b.local", "duration_ms": 20, "bytes_up": 20, "bytes_down": 7, "port": 443, "status": 200}'
    ndjson.write_text(first + "\n", encoding="utf-8")

    run1 = _run_ingest(
        "--ndjson",
        str(ndjson),
        "--csv-out",
        str(out_csv),
        "--state-file",
        str(state),
        "--incremental",
        "--append",
    )
    assert run1.returncode == 0
    df1 = pd.read_csv(out_csv)
    assert len(df1) == 1
    st1 = json.loads(state.read_text(encoding="utf-8"))
    assert st1["offset"] > 0

    run2 = _run_ingest(
        "--ndjson",
        str(ndjson),
        "--csv-out",
        str(out_csv),
        "--state-file",
        str(state),
        "--incremental",
        "--append",
    )
    assert run2.returncode == 0
    assert "No new valid proxy records." in run2.stdout
    df2 = pd.read_csv(out_csv)
    assert len(df2) == 1

    with ndjson.open("a", encoding="utf-8") as f:
        f.write(second + "\n")

    run3 = _run_ingest(
        "--ndjson",
        str(ndjson),
        "--csv-out",
        str(out_csv),
        "--state-file",
        str(state),
        "--incremental",
        "--append",
    )
    assert run3.returncode == 0
    df3 = pd.read_csv(out_csv)
    assert len(df3) == 2
