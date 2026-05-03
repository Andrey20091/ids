# =============================================================================
# Извлечение сырых байт IP-заголовков пакетов по потокам (ТЗ: сырые заголовки).
# =============================================================================
"""Build per-flow tensors of raw header bytes from PCAP (requires scapy)."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import numpy as np

from src.utils.scapy_logging import silence_windows_npcap_warning_if_needed

silence_windows_npcap_warning_if_needed()


def _proto_name(proto: int) -> str:
    return {6: "TCP", 17: "UDP", 1: "ICMP"}.get(int(proto), f"P{proto}")


def _flow_key_ip(ip_src: str, sport: int, ip_dst: str, dport: int, proto: int) -> str:
    """Как ``flow_key_series`` в CSV: протокол строкой (TCP/UDP/…)."""
    return f"{ip_src}|{sport}|{ip_dst}|{dport}|{_proto_name(proto)}"


def pcap_per_flow_header_bytes(
    pcap_path: str | Path,
    max_packets: int = 24,
    bytes_per_packet: int = 40,
    only_keys: set[str] | None = None,
    max_read_packets: int | None = None,
) -> dict[str, np.ndarray]:
    """
    Для каждого 5-tuple накопить до ``max_packets`` срезов сырых байт (IP-слой).

    Если задан ``only_keys``, обрабатываются только эти потоки; при заполнении всех
    до ``max_packets`` — досрочный выход. ``max_read_packets`` ограничивает число
    просмотренных пакетов (ускорение на огромных PCAP при частичном покрытии).

    Возвращает словарь flow_key -> ``uint8`` массив формы (max_packets, bytes_per_packet),
    недостающее дополнено нулями.
    """
    try:
        from scapy.layers.inet import IP
        from scapy.utils import PcapReader
    except ImportError as e:
        raise ImportError("Install scapy: pip install scapy") from e

    p = Path(pcap_path)
    if not p.is_file():
        raise FileNotFoundError(pcap_path)

    buckets: dict[str, list[bytes]] = defaultdict(list)
    target = only_keys
    n_target = len(target) if target is not None else 0
    filled: set[str] = set()

    pkt_seen = 0
    with PcapReader(str(p)) as reader:
        for pkt in reader:
            pkt_seen += 1
            if max_read_packets is not None and pkt_seen > max_read_packets:
                break
            if not pkt.haslayer("IP"):
                continue
            ip = pkt["IP"]
            proto = int(ip.proto)
            sport, dport = 0, 0
            if proto == 6 and pkt.haslayer("TCP"):
                tcp = pkt["TCP"]
                sport, dport = int(tcp.sport), int(tcp.dport)
            elif proto == 17 and pkt.haslayer("UDP"):
                udp = pkt["UDP"]
                sport, dport = int(udp.sport), int(udp.dport)
            k_fwd = _flow_key_ip(ip.src, sport, ip.dst, dport, proto)
            k_rev = _flow_key_ip(ip.dst, dport, ip.src, sport, proto)
            if target is not None:
                if k_fwd in target:
                    key = k_fwd
                elif k_rev in target:
                    key = k_rev
                else:
                    continue
            else:
                key = k_fwd
            raw = bytes(ip)[:bytes_per_packet]
            chunk = buckets[key]
            if len(chunk) < max_packets:
                chunk.append(raw)
                if target is not None and len(chunk) >= max_packets and key not in filled:
                    filled.add(key)
                    if len(filled) >= n_target:
                        break

    out: dict[str, np.ndarray] = {}
    for key, chunks in buckets.items():
        mat = np.zeros((max_packets, bytes_per_packet), dtype=np.uint8)
        for i, chunk in enumerate(chunks[:max_packets]):
            raw = bytes(chunk)[:bytes_per_packet]
            mat[i, : len(raw)] = np.frombuffer(raw, dtype=np.uint8)
        out[key] = mat
    return out


def tensors_dict_to_flat_npz(
    tensors: dict[str, np.ndarray],
    out_path: str | Path,
) -> None:
    """Сохранить ``keys`` + плоский ``X`` (n, max_packets * bytes_per_packet) для обучения CNN."""
    out_path = Path(out_path)
    if not tensors:
        np.savez_compressed(out_path, keys=np.array([], dtype=object), X=np.zeros((0, 0), dtype=np.uint8))
        return
    keys = sorted(tensors.keys())
    mats = [tensors[k].reshape(-1) for k in keys]
    X = np.stack(mats, axis=0).astype(np.uint8)
    np.savez_compressed(out_path, keys=np.array(keys, dtype=object), X=X)
