from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pandas as pd

from src.online.buffer_maintain_core import build_maintain_plan, estimate_csv_utf8_bytes
from src.online.buffer_rotation import buffer_meta_path, read_rotation_generation

EXIT_MIB_NOT_SATISFIED = 2


def test_build_maintain_plan_keep_rows_only(tmp_path: Path) -> None:
    p = tmp_path / "b.csv"
    df = pd.DataFrame({"a": range(12), "b": list("x" * 12)})
    df.to_csv(p, index=False)
    fb = p.stat().st_size
    df2 = pd.read_csv(p)
    plan = build_maintain_plan(df2, file_bytes=fb, keep_mb=0.0, keep_rows=4)
    assert plan.needs_action
    assert plan.tail_keep == 4
    assert plan.head_n == 8
    assert plan.estimated_tail_csv_bytes == estimate_csv_utf8_bytes(df2.iloc[-4:])


def test_build_maintain_plan_tiny_mb_forces_shrink(tmp_path: Path) -> None:
    """MiB-лимит жёсткий — хвост подбирается так, чтобы UTF-8 CSV после to_csv уместился."""
    df = pd.DataFrame({"a": range(20)})
    p = tmp_path / "t.csv"
    df.to_csv(p, index=False)
    fb = p.stat().st_size
    df2 = pd.read_csv(p)
    cap_mb = 0.00005
    cap_b = int(cap_mb * 1024 * 1024)
    assert fb > cap_b
    plan = build_maintain_plan(df2, file_bytes=fb, keep_mb=cap_mb, keep_rows=0)
    assert plan.needs_action
    assert plan.tail_keep >= 1
    assert plan.estimated_tail_csv_bytes <= cap_b + 256


def test_build_maintain_plan_flags_mib_unreachable(tmp_path: Path) -> None:
    df = pd.DataFrame({"a": ["x" * 50000]})
    p = tmp_path / "h.csv"
    df.to_csv(p, index=False)
    fb = p.stat().st_size
    plan = build_maintain_plan(pd.read_csv(p), file_bytes=fb, keep_mb=0.00001, keep_rows=0)
    assert plan.mib_goal_unreachable
    assert plan.max_single_row_utf8_bytes > int(0.00001 * 1024 * 1024)


def test_maintain_script_execute_returns_2_when_tail_row_wider_than_mib(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    buf = tmp_path / "wide.csv"
    pd.DataFrame({"a": ["x" * 40000, "y" * 40000]}).to_csv(buf, index=False)
    arch = tmp_path / "arch2"
    arch.mkdir(exist_ok=True)
    proc = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "online_buffer_maintain.py"),
            "--buffer",
            str(buf.resolve()),
            "--archive-dir",
            str(arch.resolve()),
            "--keep-last-mb",
            "0.0001",
            "--execute",
        ],
        cwd=str(root),
        env={**os.environ, "IDS_GEOIP_QUIET": "1"},
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == EXIT_MIB_NOT_SATISFIED


def test_maintain_script_dry_run_subprocess(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    buf = tmp_path / "flows_online_buffer.csv"
    pd.DataFrame({"a": range(15), "is_attack": [0, 1] * 7 + [0]}).to_csv(buf, index=False)
    proc = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "online_buffer_maintain.py"),
            "--buffer",
            str(buf.resolve()),
            "--archive-dir",
            str((tmp_path / "arch").resolve()),
            "--keep-last-rows",
            "3",
        ],
        cwd=str(root),
        env={**os.environ, "IDS_GEOIP_QUIET": "1"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    out = (proc.stdout or "") + (proc.stderr or "")
    assert "[maintain] plan:" in out
    assert "keep_tail=3" in out
    assert "dry-run" in out.lower() or "execute" in out.lower()


def test_maintain_script_execute_updates_buffer_and_meta(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    buf = tmp_path / "flows_online_buffer.csv"
    pd.DataFrame({"x": range(10), "y": list(range(10))}).to_csv(buf, index=False)
    arch = tmp_path / "arch"
    arch.mkdir(exist_ok=True)
    assert read_rotation_generation(buf) == 0
    proc = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "online_buffer_maintain.py"),
            "--buffer",
            str(buf.resolve()),
            "--archive-dir",
            str(arch.resolve()),
            "--keep-last-rows",
            "4",
            "--execute",
        ],
        cwd=str(root),
        env={**os.environ, "IDS_GEOIP_QUIET": "1"},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    left = pd.read_csv(buf)
    assert len(left) == 4
    assert left["x"].tolist() == [6, 7, 8, 9]
    archived = list(arch.glob("flows_online_buffer_archive_*.csv"))
    assert len(archived) == 1
    arc_df = pd.read_csv(archived[0])
    assert len(arc_df) == 6
    meta = buffer_meta_path(buf)
    assert meta.is_file()
    data = json.loads(meta.read_text(encoding="utf-8"))
    assert data.get("rotation_generation") == 1
