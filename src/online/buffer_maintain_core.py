# =============================================================================
# Планирование усечения online-буфера (точный учёт MiB через размер CSV хвоста).
# =============================================================================
from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Any

import pandas as pd

# Согласовано с record в online_buffer_maintain.py (оценка ≈ факт на диске).
CSV_WRITE_KWARGS: dict[str, Any] = {"index": False, "encoding": "utf-8", "lineterminator": "\n"}


def estimate_csv_utf8_bytes(df: pd.DataFrame) -> int:
    """Размер UTF-8 после to_csv (те же kwargs, что и при записи буфера), без записи на диск."""
    buf = io.StringIO()
    df.to_csv(buf, **CSV_WRITE_KWARGS)
    return len(buf.getvalue().encode("utf-8"))


def smallest_tail_rows_within_mb(df: pd.DataFrame, limit_bytes: int) -> int:
    """
    Минимальное k >= 1 такое, что UTF-8 размер ``df.iloc[-k:]`` не превышает limit_bytes.
    Монотонно уменьшаем k, если из‑за дисперсии длины строк даже бинарный поиск дал завышение.
    """
    n = len(df)
    if n == 0:
        return 0
    if limit_bytes <= 0:
        return n
    lo, hi = 1, n
    best = n
    while lo <= hi:
        mid = (lo + hi) // 2
        sz = estimate_csv_utf8_bytes(df.iloc[-mid:])
        if sz <= limit_bytes:
            best = mid
            hi = mid - 1
        else:
            lo = mid + 1
    k = best
    while k > 1 and estimate_csv_utf8_bytes(df.iloc[-k:]) > limit_bytes:
        k -= 1
    return max(1, k)


@dataclass(frozen=True)
class MaintainPlan:
    n_rows: int
    file_bytes: int
    tail_keep: int
    head_n: int
    estimated_tail_csv_bytes: int
    needs_action: bool
    mib_goal_unreachable: bool
    max_single_row_utf8_bytes: int


def max_single_row_csv_utf8_bytes(df: pd.DataFrame) -> int:
    """Максимальный UTF-8 размер одной строки как отдельного mini-CSV (пиковая «ширина» строки)."""
    if len(df) == 0:
        return 0
    m = 0
    for i in range(len(df)):
        m = max(m, estimate_csv_utf8_bytes(df.iloc[i : i + 1]))
    return m


def build_maintain_plan(
    df: pd.DataFrame,
    *,
    file_bytes: int,
    keep_mb: float,
    keep_rows: int,
) -> MaintainPlan:
    """
    Подобрать хвост с учётом MiB (бинарный поиск по k) и лимита строк (пересечение ограничений).
    """
    n_rows = len(df)
    limit_b = int(max(keep_mb, 0.0) * 1024 * 1024)
    mx_row = max_single_row_csv_utf8_bytes(df) if n_rows else 0
    mib_unreachable = limit_b > 0 and mx_row > limit_b
    caps: list[int] = []
    if keep_rows > 0:
        caps.append(min(int(keep_rows), n_rows))
    if limit_b > 0 and file_bytes > limit_b:
        k_mb = smallest_tail_rows_within_mb(df, limit_b)
        caps.append(k_mb)
    if not caps:
        return MaintainPlan(
            n_rows=n_rows,
            file_bytes=file_bytes,
            tail_keep=n_rows,
            head_n=0,
            estimated_tail_csv_bytes=estimate_csv_utf8_bytes(df) if n_rows else 0,
            needs_action=False,
            mib_goal_unreachable=mib_unreachable,
            max_single_row_utf8_bytes=mx_row,
        )
    tail_keep = min(caps)
    needs_action = tail_keep < n_rows
    est_tail = estimate_csv_utf8_bytes(df.iloc[-tail_keep:]) if tail_keep > 0 else 0
    return MaintainPlan(
        n_rows=n_rows,
        file_bytes=file_bytes,
        tail_keep=tail_keep,
        head_n=n_rows - tail_keep,
        estimated_tail_csv_bytes=est_tail,
        needs_action=needs_action,
        mib_goal_unreachable=mib_unreachable,
        max_single_row_utf8_bytes=mx_row,
    )
