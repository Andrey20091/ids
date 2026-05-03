# =============================================================================
# Исключительная блокировка на один NDJSON-лог: один процесс-писатель.
# =============================================================================
from __future__ import annotations

import os
from pathlib import Path


def acquire_log_writer_lock(log_path: Path) -> Path:
    """
    Создаёт ``<log>.writer.lock`` (O_EXCL). Если файл уже есть — выход с понятным сообщением
    (два процесса прокси не должны писать в один лог).
    """
    log_path = Path(log_path)
    lock = log_path.with_name(log_path.name + ".writer.lock")
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        raise SystemExit(
            f"Файл блокировки уже существует: {lock}\n"
            "Другой процесс прокси, возможно, пишет в тот же лог. Остановите его или удалите "
            "lock-файл, если предыдущий процесс завершился аварийно."
        ) from None
    try:
        os.write(fd, str(os.getpid()).encode("ascii", errors="replace"))
    finally:
        os.close(fd)
    return lock


def release_log_writer_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink(missing_ok=True)
    except OSError:
        pass
