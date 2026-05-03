# =============================================================================
# Чтение CSV буфера потоков (строгий UTF-8 для online/maintain).
# =============================================================================
from __future__ import annotations

import io
from pathlib import Path

import pandas as pd

_MSG_UTF8 = (
    "Файл буфера должен быть в кодировке UTF-8 (без BOM). "
    "Перекодируйте CSV в UTF-8 и повторите операцию."
)


def read_flows_buffer_csv(path: str | Path, *, low_memory: bool = False, **kwargs: object) -> pd.DataFrame:
    """Читает буфер как UTF-8; при неверной кодировке — понятная ошибка."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{_MSG_UTF8} ({p})") from e
    return pd.read_csv(io.StringIO(text), low_memory=low_memory, **kwargs)  # type: ignore[arg-type]
