# =============================================================================
# PCAP → последовательности первых K пакетов на поток (покадровые признаки для LSTM).
# =============================================================================
"""Без расшифровки L7/TLS; только заголовки IP/TCP/UDP и метаданные."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from src.features.flow_key import flow_key_series

try:
    from scapy.all import IP, PcapReader, TCP, UDP  # noqa: PLC0415
except ImportError:
    IP = TCP = UDP = None  # type: ignore[misc, assignment]
    PcapReader = None  # type: ignore[misc, assignment]

# Фиксированная размерность признака на один пакет (см. docs/TZ_CASE4).
PACKET_FEATURE_DIM = 12
DEFAULT_K = 16


def _entropy_bytes(b: bytes) -> float:
    if not b:
        return 0.0
    counts = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(b)
    return float(-(p * np.log2(p + 1e-12)).sum())


def _pkt_features(pkt: Any) -> np.ndarray:
    """Вектор длины PACKET_FEATURE_DIM из одного IP-пакета."""
    vec = np.zeros(PACKET_FEATURE_DIM, dtype=np.float32)
    if IP not in pkt:
        return vec
    ip = pkt[IP]
    vec[0] = min(float(len(ip)), 1500.0) / 1500.0
    vec[1] = float(getattr(ip, "ttl", 64)) / 255.0
    proto = int(ip.proto)
    vec[2] = 1.0 if proto == 6 else 0.0
    vec[3] = 1.0 if proto == 17 else 0.0
    vec[4] = 1.0 if proto not in (6, 17) else 0.0
    if TCP in pkt and proto == 6:
        t = pkt[TCP]
        f = int(t.flags)
        for i in range(6):
            vec[5 + i] = float((f >> i) & 1)
        vec[11] = min(float(ip.len - len(ip)), 1500.0) / 1500.0
    elif UDP in pkt and proto == 17:
        u = pkt[UDP]
        vec[11] = min(float(u.len), 1500.0) / 1500.0
    return vec


def flow_key_from_scapy_pkt(pkt: Any) -> str | None:
    """Ключ совместимый с ``flow_key_series`` (TCP/UDP по портам)."""
    if IP not in pkt:
        return None
    ip = pkt[IP]
    sip, dip = ip.src, ip.dst
    proto = int(ip.proto)
    pname = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"P{proto}")
    if proto == 6 and TCP in pkt:
        t = pkt[TCP]
        sport, dport = int(t.sport), int(t.dport)
    elif proto == 17 and UDP in pkt:
        u = pkt[UDP]
        sport, dport = int(u.sport), int(u.dport)
    else:
        sport, dport = 0, 0
    return f"{sip}|{sport}|{dip}|{dport}|{pname}"


def extract_packet_sequences(
    pcap_path: str | Path,
    *,
    k_packets: int = DEFAULT_K,
    max_pcap_packets: int = 2_000_000,
) -> dict[str, np.ndarray]:
    """
    Вернуть словарь flow_key -> массив формы (K, PACKET_FEATURE_DIM).

    Не более ``k_packets`` первых пакетов на поток; недостающее заполняется нулями.
    """
    if PcapReader is None:
        raise ImportError("scapy required: pip install scapy")
    pcap_path = Path(pcap_path)
    buffers: dict[str, list[np.ndarray]] = defaultdict(list)
    seen = 0
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            seen += 1
            if seen > max_pcap_packets:
                break
            key = flow_key_from_scapy_pkt(pkt)
            if key is None:
                continue
            if len(buffers[key]) >= k_packets:
                continue
            buffers[key].append(_pkt_features(pkt))

    out: dict[str, np.ndarray] = {}
    for key, lst in buffers.items():
        z = np.zeros((k_packets, PACKET_FEATURE_DIM), dtype=np.float32)
        for i, row in enumerate(lst[:k_packets]):
            z[i] = row
        out[key] = z
    return out


def align_sequences_to_flows_csv(
    sequences: dict[str, np.ndarray],
    flows_df,
    flow_key_col: str = "flow_key",
) -> tuple[np.ndarray, np.ndarray]:
    """
    Выравнивание по ключам из подготовленного CSV.

    Возвращает ``X`` формы (n_rows, K, F) и ``mask`` bool — True если ключ найден в PCAP.
    """
    if flow_key_col not in flows_df.columns:
        fk = flow_key_series(flows_df)
    else:
        fk = flows_df[flow_key_col].astype(str)
    n = len(flows_df)
    k = next(iter(sequences.values())).shape[0] if sequences else DEFAULT_K
    X = np.zeros((n, k, PACKET_FEATURE_DIM), dtype=np.float32)
    mask = np.zeros(n, dtype=bool)
    seq_get = sequences.get
    for i in range(n):
        key = str(fk.iloc[i])
        seq = seq_get(key)
        if seq is not None:
            X[i] = seq
            mask[i] = True
    return X, mask


def flows_labels_binary(flows_df, label_col: str = "Label") -> np.ndarray:
    """Бинарная метка атаки для обучения пакетного LSTM."""
    if label_col not in flows_df.columns:
        return np.zeros(len(flows_df), dtype=np.int64)
    s = flows_df[label_col].astype(str).str.upper()
    y = (~s.eq("BENIGN")).astype(np.int64)
    return y.values
