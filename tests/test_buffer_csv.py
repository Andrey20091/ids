from __future__ import annotations

from pathlib import Path

import pytest

from src.utils.buffer_csv import read_flows_buffer_csv


def test_read_flows_buffer_csv_rejects_non_utf8(tmp_path: Path) -> None:
    p = tmp_path / "b.csv"
    p.write_bytes(b"a\n\xff\xfe\n")
    with pytest.raises(ValueError, match="UTF-8"):
        read_flows_buffer_csv(p, low_memory=False)
