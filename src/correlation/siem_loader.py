# =============================================================================
# Загрузка событий SIEM из JSON / NDJSON / HTTP (кейс 4).
# =============================================================================
"""Load SIEM events from JSON, NDJSON, or HTTP endpoint."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pandas as pd
import requests


def _normalize_siem_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Поддержка распространённых алиасов полей (NDJSON / SIEM-экспорты)."""
    if df.empty:
        return df
    out = df.copy()
    if "ip" not in out.columns:
        for alt in ("client_ip", "source_ip", "src_ip", "host_ip"):
            if alt in out.columns:
                out["ip"] = out[alt]
                break
    else:
        for alt in ("client_ip", "source_ip", "src_ip", "host_ip"):
            if alt in out.columns:
                out["ip"] = out["ip"].where(out["ip"].notna(), out[alt])
                break
    if "event_type" not in out.columns:
        for alt in ("event", "evt", "type", "eventName"):
            if alt in out.columns:
                out["event_type"] = out[alt]
                break
    else:
        for alt in ("event", "evt", "type", "eventName"):
            if alt in out.columns:
                out["event_type"] = out["event_type"].where(
                    out["event_type"].notna(), out[alt]
                )
                break
    return out


def load_siem_events(path: str | Path) -> pd.DataFrame:
    """
    Прочитать JSON-массив событий SIEM и вернуть ``DataFrame``.

    Ожидаемые поля: как минимум ``ip``, ``event_type`` (см. ``correlation_rules``).
    """
    p = Path(path)
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    df = pd.DataFrame(data)
    return _normalize_siem_columns(df)


def load_siem_events_ndjson(path: str | Path) -> pd.DataFrame:
    """
    Прочитать **NDJSON** (один JSON-объект на строку) — частый формат стриминга логов.

    Поддерживаемые поля: ``ip`` (или ``client_ip``), ``event_type`` (или ``evt``),
    опционально ``timestamp``, ``severity``.
    """
    p = Path(path)
    rows: list[dict] = []
    with open(p, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    if not rows:
        return pd.DataFrame()
    return _normalize_siem_columns(pd.DataFrame(rows))


def load_siem_events_http(
    url: str,
    timeout_seconds: int = 5,
    retries: int = 0,
    retry_backoff_seconds: float = 0.2,
) -> pd.DataFrame:
    """
    Загрузить SIEM-события по HTTP(S) с endpoint, возвращающим JSON-массив.
    """
    if not url:
        return pd.DataFrame()
    retries = max(0, int(retries))
    backoff = max(0.0, float(retry_backoff_seconds))
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, timeout=timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, list):
                return pd.DataFrame()
            return _normalize_siem_columns(pd.DataFrame(data))
        except requests.RequestException as e:
            last_err = e
            if attempt < retries:
                time.sleep(backoff * (attempt + 1))
            continue
    if last_err is not None:
        raise last_err
    return pd.DataFrame()
