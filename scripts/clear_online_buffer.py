# =============================================================================
# Очистка online-буфера: только заголовок CSV + сброс watermark + поколение буфера.
# =============================================================================
"""Усечь flows_online_buffer до заголовка; удалить watermark online; +1 rotation_generation."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.online.buffer_rotation import increment_rotation_generation
from src.utils.console_encoding import configure_stdio_utf8
from src.utils_config import load_settings, resolve_from_project_root


def main() -> int:
    configure_stdio_utf8()
    parser = argparse.ArgumentParser(description="Усечь online buffer CSV до заголовка и сбросить watermark")
    parser.add_argument(
        "--buffer",
        default="",
        help="Путь к буферу (пусто = paths.flows_online_buffer из settings.yaml)",
    )
    args = parser.parse_args()

    settings = load_settings()
    buf_rel = (args.buffer or "").strip()
    if buf_rel:
        buf_path = resolve_from_project_root(buf_rel).resolve()
    else:
        rel = (settings.get("paths", {}) or {}).get("flows_online_buffer", "data/processed/flows_online_buffer.csv")
        buf_path = resolve_from_project_root(rel).resolve()

    if not buf_path.is_file():
        print(f"Файл буфера не найден: {buf_path}")
        return 1

    text = buf_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        print("Файл пустой.")
        return 1
    header = lines[0]
    buf_path.write_text(header + "\n", encoding="utf-8")

    gen = increment_rotation_generation(buf_path)
    wm = (_ROOT / "storage" / "online_buffer_watermark.json").resolve()
    if wm.is_file():
        wm.unlink()
        print(f"Удалён watermark: {wm}")

    inc = (_ROOT / "storage" / "detect_incremental_state.json").resolve()
    if inc.is_file():
        inc.unlink()
        print(f"Удалён state инкрементального detect: {inc}")

    print(f"Буфер усечён до заголовка: {buf_path}")
    print(f"rotation_generation={gen}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
