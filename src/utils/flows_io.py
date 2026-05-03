# =============================================================================
# Загрузка flows.csv с ограничением строк и опциональным parquet-кэшем.
# =============================================================================
"""Fast path: nrows instead of full read + head; optional parquet cache (pyarrow)."""

from __future__ import annotations

from pathlib import Path
import warnings

import pandas as pd


def read_flows_csv(
    csv_path: Path,
    *,
    row_limit: int | None,
    parquet_cache: bool,
    csv_engine: str | None,
) -> pd.DataFrame:
    """
    Читает CSV с ``nrows=row_limit`` (не грузит весь гигабайтный файл в RAM).
    При ``parquet_cache`` сохраняет/читает ``.cache/<stem>_n<limit>.parquet`` если pyarrow доступен.
    ``row_limit`` <= 0 — читать все строки.
    """
    csv_path = csv_path.resolve()
    engine_kw: dict = {}
    if csv_engine == "pyarrow":
        engine_kw["engine"] = "pyarrow"
    elif csv_engine == "c":
        engine_kw["engine"] = "c"

    nrows = None if row_limit is None or row_limit <= 0 else int(row_limit)

    if parquet_cache and nrows is not None and nrows > 0:
        cache_dir = csv_path.parent / ".cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = cache_dir / f"{csv_path.stem}_n{nrows}.parquet"
        if cache_path.is_file():
            try:
                if cache_path.stat().st_mtime >= csv_path.stat().st_mtime:
                    return pd.read_parquet(cache_path)
            except Exception as e:
                warnings.warn(
                    f"Parquet cache read failed, fallback to CSV ({e}).",
                    UserWarning,
                    stacklevel=2,
                )

    try:
        df = pd.read_csv(
            csv_path,
            encoding="utf-8",
            encoding_errors="replace",
            low_memory=False,
            nrows=nrows,
            **engine_kw,
        )
    except Exception as exc:
        if engine_kw:
            print(f"Предупреждение: движок CSV {csv_engine} недоступен ({exc}); повтор без engine=.")
            df = pd.read_csv(
                csv_path,
                encoding="utf-8",
                encoding_errors="replace",
                low_memory=False,
                nrows=nrows,
            )
        else:
            raise
    if parquet_cache and nrows is not None and nrows > 0:
        cache_dir = csv_path.parent / ".cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = cache_dir / f"{csv_path.stem}_n{nrows}.parquet"
        try:
            df.to_parquet(cache_path, index=False)
        except Exception as e:
            warnings.warn(
                f"Parquet cache write skipped ({e}).",
                UserWarning,
                stacklevel=2,
            )
    return df
