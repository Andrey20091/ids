# =============================================================================
# Доп. признаки HTTP (plaintext) / DNS из PCAP без TLS decryption.
# =============================================================================
"""Сканирование pcap: не инспектируем зашифрованный L7; порт 80 / DNS UDP 53."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

try:
    from scapy.all import DNS, IP, PcapReader, Raw, TCP, UDP  # noqa: PLC0415
except ImportError:
    IP = None  # type: ignore[misc, assignment]

from src.ingest.pcap_packet_sequences import flow_key_from_scapy_pkt


def _entropy_str(s: str) -> float:
    if not s:
        return 0.0
    b = s.encode("utf-8", errors="replace")
    if not b:
        return 0.0
    c = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = c[c > 0] / len(b)
    return float(-(p * np.log2(p + 1e-12)).sum())


def collect_plaintext_flow_stats(
    pcap_path: str | Path,
    *,
    max_pcap_packets: int = 1_000_000,
) -> dict[str, dict[str, float]]:
    """
    По flow_key -> max длина QNAME, max entropy, max длина первой строки HTTP (если TCP/80).
    """
    if IP is None:
        raise ImportError("scapy required")
    out: dict[str, dict[str, list[float]]] = defaultdict(
        lambda: {"dns_len": [], "dns_ent": [], "http_line": []}
    )
    seen = 0
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            seen += 1
            if seen > max_pcap_packets:
                break
            key = flow_key_from_scapy_pkt(pkt)
            if key is None:
                continue
            if UDP in pkt and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53):
                if DNS in pkt:
                    dn = pkt[DNS]
                    qd = getattr(dn, "qd", None)
                    q = qd.qname.decode(errors="replace").rstrip(".") if qd is not None and qd.qname else ""
                    if q:
                        out[key]["dns_len"].append(float(len(q)))
                        out[key]["dns_ent"].append(_entropy_str(q))
            elif TCP in pkt:
                sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
                if sport == 80 or dport == 80:
                    raw = pkt[Raw].load if Raw in pkt else b""
                    try:
                        line = raw.split(b"\r\n", 1)[0][:512].decode("latin-1", errors="replace")
                        if line.startswith(("GET ", "POST ", "PUT ", "HEAD ", "HTTP/")):
                            out[key]["http_line"].append(float(len(line)))
                    except Exception:
                        pass

    flat: dict[str, dict[str, float]] = {}
    for key, d in out.items():
        flat[key] = {
            "pcap_dns_qname_len_max": max(d["dns_len"]) if d["dns_len"] else 0.0,
            "pcap_dns_qname_entropy_max": max(d["dns_ent"]) if d["dns_ent"] else 0.0,
            "pcap_http_first_line_len_max": max(d["http_line"]) if d["http_line"] else 0.0,
            "pcap_plaintext_hits": float(bool(d["dns_len"] or d["http_line"])),
        }
    return flat


def merge_plaintext_stats_into_df(df: pd.DataFrame, stats: dict[str, dict[str, float]]) -> pd.DataFrame:
    """Слияние по колонке ``flow_key``."""
    out = df.copy()
    fk = out["flow_key"].astype(str) if "flow_key" in out.columns else None
    if fk is None:
        return out
    for col in ("pcap_dns_qname_len_max", "pcap_dns_qname_entropy_max", "pcap_http_first_line_len_max", "pcap_plaintext_hits"):
        out[col] = fk.map(lambda k: stats.get(k, {}).get(col, 0.0)).astype(float)
    return out
