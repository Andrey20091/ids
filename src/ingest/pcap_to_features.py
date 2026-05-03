# =============================================================================
# PCAP → табличные признаки потоков (опционально; требуется scapy).
# =============================================================================
"""
PCAP → tabular flow features (optional).

Извлекает агрегаты по 5-tuple и **поля IP/TCP заголовков** (TTL, TCP window, флаги),
что соответствует ТЗ кейса 4 («сырые заголовки» → числовой вектор + дальнейший embedding).

Requires: pip install scapy
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pandas as pd

from src.utils.scapy_logging import silence_windows_npcap_warning_if_needed

silence_windows_npcap_warning_if_needed()


def _proto_name(proto: int) -> str:
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(proto), f"P{proto}")


def pcap_to_flow_dataframe(pcap_path: str | Path) -> pd.DataFrame:
    """
    Построить таблицу потоков из PCAP: длительность, объёмы, счётчики флагов, TTL, TCP window.

    Полный паритет со всеми колонками CICIDS2017 достигается на этапе ``ensure_flow_schema_for_ml``
    (недостающие поля заполняются нулями).
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.utils import PcapReader
    except ImportError as e:
        raise ImportError("Install scapy: pip install scapy") from e

    p = Path(pcap_path)
    if not p.is_file():
        raise FileNotFoundError(pcap_path)

    def _blank() -> dict:
        return {
            "t0": None,
            "t1": None,
            "count": 0,
            "bytes": 0,
            "ttl_sum": 0,
            "ttl_n": 0,
            "wmax": 0,
            "syn": 0,
            "fin": 0,
            "rst": 0,
            "plen_max": 0,
            "plen_min": None,
        }

    flows: dict[tuple, dict] = defaultdict(_blank)

    with PcapReader(str(p)) as reader:
        for pkt in reader:
            if not pkt.haslayer("IP"):
                continue
            ip = pkt["IP"]
            proto = int(ip.proto)
            sport, dport = 0, 0
            if proto == 6 and pkt.haslayer("TCP"):
                tcp = pkt["TCP"]
                sport, dport = int(tcp.sport), int(tcp.dport)
            elif proto == 17 and pkt.haslayer("UDP"):
                sport, dport = int(pkt["UDP"].sport), int(pkt["UDP"].dport)
            key = (ip.src, sport, ip.dst, dport, proto)
            st = flows[key]
            if proto == 6 and pkt.haslayer("TCP"):
                tcp = pkt["TCP"]
                flags = int(tcp.flags)
                if flags & 0x02:
                    st["syn"] += 1
                if flags & 0x01:
                    st["fin"] += 1
                if flags & 0x04:
                    st["rst"] += 1
                st["wmax"] = max(st["wmax"], int(tcp.window))
            t = float(pkt.time)
            if st["t0"] is None:
                st["t0"] = t
            st["t1"] = t
            st["count"] += 1
            plen = len(pkt)
            st["bytes"] += plen
            st["ttl_sum"] += int(ip.ttl)
            st["ttl_n"] += 1
            st["plen_max"] = max(st["plen_max"], plen)
            if st["plen_min"] is None:
                st["plen_min"] = plen
            else:
                st["plen_min"] = min(st["plen_min"], plen)

    rows: list[dict] = []
    for key, st in flows.items():
        src, sport, dst, dport, proto = key
        t0, t1 = st["t0"], st["t1"]
        dur_s = float(t1) - float(t0) if t0 is not None and t1 is not None else 0.0
        dur_s = max(dur_s, 1e-9)
        cnt = max(int(st["count"]), 1)
        ttl_n = int(st["ttl_n"])
        ip_ttl_mean = float(st["ttl_sum"]) / ttl_n if ttl_n else 0.0
        plmin = int(st["plen_min"]) if st["plen_min"] is not None else 0
        rows.append(
            {
                "Source IP": src,
                "Destination IP": dst,
                "Source Port": sport,
                "Destination Port": dport,
                "Protocol": _proto_name(proto),
                "Flow Duration": int(dur_s * 1_000_000),
                "Total Fwd Packets": int(st["count"]),
                "Total Backward Packets": 0,
                "Fwd Packet Length Max": int(st["plen_max"]),
                "Fwd Packet Length Min": plmin,
                "Fwd Packet Length Mean": float(st["bytes"]) / cnt,
                "Bwd Packet Length Max": 0,
                "Flow Bytes/s": float(st["bytes"]) / dur_s,
                "Flow Packets/s": float(st["count"]) / dur_s,
                "SYN Flag Count": int(st["syn"]),
                "FIN Flag Count": int(st["fin"]),
                "RST Flag Count": int(st["rst"]),
                "ip_ttl_mean": ip_ttl_mean,
                "tcp_window_max": float(st["wmax"]),
            }
        )

    return pd.DataFrame(rows)


def pcap_to_flow_features_stub(pcap_path: str | Path) -> None:
    """Устаревшее имя: вызывает ``pcap_to_flow_dataframe`` или ошибку без scapy."""
    pcap_to_flow_dataframe(pcap_path)
