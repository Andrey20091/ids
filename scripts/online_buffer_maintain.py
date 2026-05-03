# =============================================================================
# Обслуживание размера online-буфера: перенос «головы» в архив (dry-run по умолчанию).
# =============================================================================
"""См. README: «Буфер и обслуживание», scripts/online_buffer_maintain.py --help."""

from __future__ import annotations

import argparse
import os
import sys
import warnings
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

import pandas as pd

from src.governance.storage import utc_now_iso
from src.online.buffer_maintain_core import CSV_WRITE_KWARGS, build_maintain_plan, smallest_tail_rows_within_mb
from src.online.buffer_rotation import increment_rotation_generation
from src.utils.buffer_csv import read_flows_buffer_csv
from src.utils.console_encoding import configure_stdio_utf8
from src.utils_config import load_settings, resolve_from_project_root

EXIT_MIB_NOT_SATISFIED = 2


def main() -> int:
    configure_stdio_utf8()
    parser = argparse.ArgumentParser(
        description="Перенос старых строк online-буфера в архивный CSV. По умолчанию только план (dry-run)."
    )
    parser.add_argument(
        "--buffer",
        type=str,
        default="",
        help="Путь к CSV буфера (пусто = paths.flows_online_buffer из settings.yaml)",
    )
    parser.add_argument("--archive-dir", type=str, default="storage/archive_flows")
    parser.add_argument(
        "--keep-last-mb",
        type=float,
        default=0.0,
        help="Целевой потолок размера файла (MiB); учитывается если файл больше этого порога",
    )
    parser.add_argument("--keep-last-rows", type=int, default=0, help="Максимум последних строк в активном буфере")
    parser.add_argument(
        "--buffer-encoding",
        type=str,
        default="utf-8",
        help="Поддерживается только utf-8 (буфер должен быть UTF-8 без BOM).",
    )
    parser.add_argument("--execute", action="store_true", help="Выполнить перенос и усечение буфера")
    args = parser.parse_args()

    if str(args.buffer_encoding).strip().lower() not in ("utf8", "utf-8"):
        print(
            "Поддерживается только --buffer-encoding utf-8; конвертируйте файл в UTF-8.",
            file=sys.stderr,
        )
        return 1

    settings = load_settings()
    buf_arg = (args.buffer or "").strip()
    if buf_arg:
        buf_path = resolve_from_project_root(buf_arg).resolve()
    else:
        rel = (settings.get("paths", {}) or {}).get("flows_online_buffer", "data/processed/flows_online_buffer.csv")
        buf_path = resolve_from_project_root(rel).resolve()

    keep_mb = float(args.keep_last_mb or 0.0)
    keep_rows = int(args.keep_last_rows or 0)
    if keep_mb <= 0 and keep_rows <= 0:
        raise SystemExit("Укажите --keep-last-mb и/или --keep-last-rows.")

    if not buf_path.is_file():
        print(f"Нет файла буфера: {buf_path}")
        return 1

    try:
        df = read_flows_buffer_csv(buf_path, low_memory=False)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 1

    file_bytes = buf_path.stat().st_size
    plan = build_maintain_plan(df, file_bytes=file_bytes, keep_mb=keep_mb, keep_rows=keep_rows)

    if keep_mb > 0 and plan.mib_goal_unreachable:
        print(
            f"[maintain] WARN: одна строка CSV доходит до ~{plan.max_single_row_utf8_bytes} B при лимите "
            f"{int(keep_mb * 1024 * 1024)} B — цель MiB для всего файла может быть недостижима.",
            file=sys.stderr,
        )

    if not plan.needs_action:
        print(f"[maintain] без действий: строк={plan.n_rows}, байт={plan.file_bytes} — пороги не требуют усечения.")
        return 0

    arch_root = resolve_from_project_root(args.archive_dir)
    arch_root.mkdir(parents=True, exist_ok=True)
    stamp = utc_now_iso().replace(":", "").replace("-", "").replace("T", "_")[:20]
    arch_path = arch_root / f"{buf_path.stem}_archive_{stamp}.csv"

    print(f"[maintain] buffer={buf_path}")
    print(f"[maintain] текущее: строк={plan.n_rows}, байт={plan.file_bytes}")
    print(f"[maintain] plan: archive_rows={plan.head_n} keep_tail={plan.tail_keep}")
    print(f"[maintain] план: в архив строк={plan.head_n}, оставить хвост={plan.tail_keep}")
    print(
        f"[maintain] оценка UTF-8 размера хвоста после write_csv ≈ {plan.estimated_tail_csv_bytes} байт "
        f"(бинарный подбор по MiB при необходимости)"
    )
    print(f"[maintain] архив: {arch_path}")
    if not args.execute:
        print("[maintain] dry-run — для записи добавьте --execute.")
        return 0

    head = df.iloc[: plan.head_n]
    tail = df.iloc[plan.head_n :]
    head.to_csv(arch_path, **CSV_WRITE_KWARGS)
    tail.to_csv(buf_path, **CSV_WRITE_KWARGS)
    increment_rotation_generation(buf_path)
    print(f"[maintain] готово: {arch_path}, буфер обновлён, rotation_generation увеличен.")

    mib_failed = False
    if keep_mb > 0:
        limit_b = int(keep_mb * 1024 * 1024)
        for round_i in range(1, 4):
            sz = buf_path.stat().st_size
            if sz <= limit_b:
                break
            try:
                df_r = read_flows_buffer_csv(buf_path, low_memory=False)
            except ValueError as e:
                print(str(e), file=sys.stderr)
                return 1
            if len(df_r) <= 1:
                print(
                    "[maintain] ERROR: буфер всё ещё выше MiB-лимита; одна строка CSV может быть шире лимита — "
                    "перекодируйте/урежьте строку или увеличьте --keep-last-mb.",
                    file=sys.stderr,
                )
                mib_failed = True
                break
            k = smallest_tail_rows_within_mb(df_r, limit_b)
            extra = df_r.iloc[:-k]
            tail_only = df_r.iloc[-k:]
            if len(extra) == 0:
                break
            extra.to_csv(arch_path, mode="a", header=False, **CSV_WRITE_KWARGS)
            tail_only.to_csv(buf_path, **CSV_WRITE_KWARGS)
            print(
                f"[maintain] refine round {round_i}: размер на диске был {sz}, "
                f"доп. строк в архив={len(extra)}, хвост={k}"
            )
            if buf_path.stat().st_size <= limit_b:
                break
        final_sz = buf_path.stat().st_size
        if final_sz > limit_b:
            print(
                f"[maintain] ERROR: после уточняющих проходов размер буфера ({final_sz} B) всё ещё выше лимита "
                f"({limit_b} B). Одна строка может превышать MiB — задайте больший лимит или урежьте строки.",
                file=sys.stderr,
            )
            mib_failed = True

    return EXIT_MIB_NOT_SATISFIED if mib_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
