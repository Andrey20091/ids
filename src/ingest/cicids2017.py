# =============================================================================
# CICIDS2017: нормализация имён колонок и полная схема под ML (кейс 4, ТЗ).
# =============================================================================
"""Normalize official CICIDS2017 CSV exports and fill missing columns for PCAP/minimal inputs."""

from __future__ import annotations

from pathlib import Path

import pandas as pd


def _normalize_timestamp_series(ts: pd.Series) -> pd.Series:
    """
    ISO-строки (прокси, экспорт YYYY-MM-DD) без dayfirst=True — без предупреждений pandas.
    Остальное (DD/MM/YYYY как в CICIDS TrafficLabelling) — с dayfirst=True.
    """
    if pd.api.types.is_datetime64_any_dtype(ts):
        return ts
    s_str = ts.astype(str)
    # NaN / пусто → NaT
    valid = ts.notna() & s_str.str.strip().ne("") & ~s_str.str.lower().isin(("nan", "nat", "none"))
    out = pd.Series(pd.NaT, index=ts.index, dtype="datetime64[ns]")
    # Строки вида YYYY-MM-DD или YYYY/MM/DD в начале (частый proxy / ISO)
    iso_start = valid & s_str.str.match(r"^\s*\d{4}[-/]\d{2}[-/]\d{2}", na=False)
    if iso_start.any():
        out.loc[iso_start] = pd.to_datetime(ts[iso_start], errors="coerce", dayfirst=False)
    rest = valid & ~iso_start
    if rest.any():
        out.loc[rest] = pd.to_datetime(ts[rest], errors="coerce", dayfirst=True)
    return out


def normalize_cicids2017_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Привести таблицу к ожидаемым именам колонок CICIDS2017 / ISC X.

    - убирает BOM и пробелы по краям имён;
    - приводит распространённые варианты метки к ``Label``.
    """
    out = df.copy()
    out.columns = [str(c).strip().lstrip("\ufeff").strip() for c in out.columns]
    lower_map = {c.lower(): c for c in out.columns}
    if "Label" not in out.columns:
        for candidate in ("label", "labels"):
            if candidate in lower_map:
                src = lower_map[candidate]
                out = out.rename(columns={src: "Label"})
                break
    if "Timestamp" in out.columns and not pd.api.types.is_datetime64_any_dtype(out["Timestamp"]):
        out["Timestamp"] = _normalize_timestamp_series(out["Timestamp"])
    return out


def ensure_flow_schema_for_ml(df: pd.DataFrame, feat_cfg: dict) -> pd.DataFrame:
    """
    Добавить отсутствующие колонки из ``feature_columns.yaml`` нулями/дефолтами.

    Нужно для PCAP→CSV и неполных экспортов, чтобы пайплайн совпадал с CICIDS-вектором (ТЗ).
    """
    out = df.copy()
    label_col = feat_cfg.get("label_column", "Label")
    if label_col not in out.columns:
        out[label_col] = "BENIGN"

    ts_col = feat_cfg.get("timestamp_column")
    if ts_col and ts_col not in out.columns:
        if len(out) == 0:
            out[ts_col] = pd.Series(dtype="datetime64[ns]")
        else:
            base = pd.Timestamp.now()
            out[ts_col] = pd.date_range(start=base, periods=len(out), freq="ms")

    _enriched_prefixes = ("http_", "dns_", "hdr_", "hb_")
    for c in feat_cfg.get("numeric_features", []):
        if c.startswith(_enriched_prefixes):
            continue
        if c not in out.columns:
            out[c] = 0.0

    cat = feat_cfg.get("categorical_for_embedding", {})
    proto_col = cat.get("protocol_column", "Protocol")
    port_col = cat.get("port_column", "Destination Port")
    if proto_col and proto_col not in out.columns:
        out[proto_col] = "TCP"
    if port_col and port_col not in out.columns:
        out[port_col] = 0

    if "Source Port" not in out.columns:
        out["Source Port"] = 0

    for c in feat_cfg.get("context_columns", []):
        if c not in out.columns:
            out[c] = "0.0.0.0"

    return out


def load_cicids2017_csv(path: str | Path, **read_csv_kwargs) -> pd.DataFrame:
    """Загрузить CSV датасета CICIDS2017 и нормализовать колонки."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"CICIDS CSV not found: {p}")
    raw = pd.read_csv(p, **read_csv_kwargs)
    return normalize_cicids2017_dataframe(raw)
