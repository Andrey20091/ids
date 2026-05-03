from __future__ import annotations

from pathlib import Path

from src.proxy.simple_proxy import rotate_log_files


def test_rotate_log_files_rolls_and_keeps_backups(tmp_path: Path):
    log = tmp_path / "proxy.ndjson"
    log.write_text("line0\n", encoding="utf-8")
    (tmp_path / "proxy.ndjson.1").write_text("line1\n", encoding="utf-8")
    (tmp_path / "proxy.ndjson.2").write_text("line2\n", encoding="utf-8")

    rotate_log_files(log, max_log_backups=2)

    assert not log.exists()
    assert (tmp_path / "proxy.ndjson.1").read_text(encoding="utf-8") == "line0\n"
    assert (tmp_path / "proxy.ndjson.2").read_text(encoding="utf-8") == "line1\n"
