# =============================================================================
# Модуль: обогащение признаков по кейсу 4 (HTTP / DNS / заголовки).
# Вызывается из prepare_data после загрузки CSV, до отбора колонок в flows.csv.
# =============================================================================
"""Обогащение табличных потоков признаками уровня L2 из кейса: HTTP, DNS, числовые заголовки."""

from __future__ import annotations

import pandas as pd

from src.features.dns_tunnel_features import dns_features_from_qname_series
from src.features.http_sequence_features import enrich_http_features
from src.features.packet_header_features import flow_header_fingerprint_numeric, select_header_numeric_columns


def enrich_case4_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Последовательно добавляет признаки, описанные в ТЗ кейса 4.

    Шаги:
      1) HTTP — длины и эвристики по URI/методу (если колонки есть).
      2) DNS — длина и энтропия QNAME (если есть колонка dns_qname).
      3) Числовые поля заголовков — копия подмножества для единообразия пайплайна.

    Параметры
    ----------
    df : pd.DataFrame
        Сырой или частично обработанный датафрейм потоков.

    Возвращает
    -----------
    pd.DataFrame
        Копия с добавленными столбцами (без удаления исходных).
    """
    # --- HTTP (последовательности запросов / URI) ---
    out = enrich_http_features(df)

    # --- DNS-туннелирование: эвристики по имени запроса ---
    if "dns_qname" in out.columns:
        dns_part = dns_features_from_qname_series(out["dns_qname"])
        out = pd.concat([out, dns_part], axis=1)
    else:
        for c in (
            "dns_qname_len",
            "dns_qname_entropy",
            "dns_label_count",
            "dns_max_label_len",
            "dns_digit_ratio",
        ):
            out[c] = 0.0

    # --- Явный набор «заголовочных» числовых признаков для embedding-пайплайна ---
    header_candidates = [
        "Flow Duration",
        "Fwd Packet Length Max",
        "Bwd Packet Length Max",
        "Flow Bytes/s",
        "Flow Packets/s",
        "SYN Flag Count",
    ]
    hdr = select_header_numeric_columns(out, header_candidates)
    if not hdr.empty:
        for c in hdr.columns:
            out[f"hdr_{c.replace(' ', '_')}"] = pd.to_numeric(hdr[c], errors="coerce").fillna(0.0)

    out["hdr_flow_fingerprint"] = flow_header_fingerprint_numeric(out)

    # Поля IP/TCP из PCAP (сырые заголовки) → единый префикс hdr_* для RF/AE/LSTM/embedding
    for raw, hdr in (
        ("ip_ttl_mean", "hdr_ip_ttl_mean"),
        ("tcp_window_max", "hdr_tcp_window_max"),
    ):
        if raw in out.columns:
            out[hdr] = pd.to_numeric(out[raw], errors="coerce").fillna(0.0)
        elif hdr not in out.columns:
            out[hdr] = 0.0

    return out
