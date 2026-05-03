# =============================================================================
# Стабильный ключ5-tuple потока (сопоставление PCAP ↔ CSV, ТЗ).
# =============================================================================
from __future__ import annotations

import pandas as pd


def _protocol_token_for_flow_key(proto_raw: pd.Series) -> pd.Series:
    """
    Официальный CICIDS2017 CSV часто даёт Protocol числом (6/17/1); PCAP-ключи — TCP/UDP/ICMP    (как ``pcap_header_bytes._flow_key_ip``). Приводим к одному виду.
    """
    num = pd.to_numeric(proto_raw, errors="coerce")
    uniq = num.dropna().unique()
    umap: dict[float, str] = {}
    for u in uniq:
        i = int(u)
        umap[float(u)] = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(i, f"P{i}")
    mapped = num.map(umap)
    str_fallback = proto_raw.astype(str).str.strip().str.upper()
    return mapped.fillna(str_fallback)


def flow_key_series(df: pd.DataFrame) -> pd.Series:
    """Построить ключ ``src|sport|dst|dport|proto`` по строкам датафрейма."""
    def col(name: str, default):
        if name in df.columns:
            return df[name]
        return pd.Series([default] * len(df), index=df.index)

    sip = col("Source IP", "").astype(str)
    sport = col("Source Port", 0).astype(str)
    dip = col("Destination IP", "").astype(str)
    dport = col("Destination Port", 0).astype(str)
    proto = _protocol_token_for_flow_key(col("Protocol", ""))
    return sip + "|" + sport + "|" + dip + "|" + dport + "|" + proto
