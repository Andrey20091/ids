from __future__ import annotations

import pytest

from src.proxy.log_writer_lock import acquire_log_writer_lock, release_log_writer_lock


def test_acquire_log_writer_lock_twice_raises(tmp_path):
    log = tmp_path / "a.ndjson"
    lock = acquire_log_writer_lock(log)
    try:
        with pytest.raises(SystemExit):
            acquire_log_writer_lock(log)
    finally:
        release_log_writer_lock(lock)


def test_release_log_writer_lock_idempotent(tmp_path):
    log = tmp_path / "b.ndjson"
    lock = acquire_log_writer_lock(log)
    release_log_writer_lock(lock)
    release_log_writer_lock(lock)
