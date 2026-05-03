# =============================================================================
# Скрипт 06: локальный HTTP/HTTPS-прокси → сырой лог NDJSON (data/raw/…).
# =============================================================================
"""Запуск asyncio-прокси; браузер указывает этот хост:порт как HTTP-прокси."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.proxy.log_writer_lock import acquire_log_writer_lock, release_log_writer_lock
from src.proxy.simple_proxy import run_proxy_server
from src.utils.console_encoding import configure_stdio_utf8


def main() -> None:
    configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="Локальный прокси с записью метаданных в NDJSON")
    parser.add_argument("--bind", default="127.0.0.1", help="Адрес прослушивания")
    parser.add_argument("--port", type=int, default=8899, help="Порт прокси")
    parser.add_argument(
        "--output",
        type=str,
        default=str(_ROOT / "data/raw/proxy_traffic.ndjson"),
        help="Путь к файлу лога (добавление строк)",
    )
    parser.add_argument(
        "--host-filter",
        default="",
        help="Разрешить только хосты, содержащие эту подстроку (без учёта регистра); пусто — все",
    )
    parser.add_argument(
        "--max-log-mb",
        type=int,
        default=0,
        help="Ротация NDJSON лога при превышении размера в MB (0 = выключено).",
    )
    parser.add_argument(
        "--max-log-backups",
        type=int,
        default=5,
        help="Число ротационных backup-файлов proxy_traffic.ndjson.N",
    )
    args = parser.parse_args()
    outp = Path(args.output)
    if not outp.is_absolute():
        outp = _ROOT / outp

    async def _run() -> None:
        await run_proxy_server(
            args.bind,
            args.port,
            outp,
            args.host_filter,
            max_log_bytes=max(0, int(args.max_log_mb or 0)) * 1024 * 1024,
            max_log_backups=max(1, int(args.max_log_backups or 1)),
        )

    lock_path = None
    try:
        lock_path = acquire_log_writer_lock(outp)
        try:
            asyncio.run(_run())
        except KeyboardInterrupt:
            print("\nПрокси остановлен.")
    finally:
        if lock_path is not None:
            release_log_writer_lock(lock_path)


if __name__ == "__main__":
    main()
