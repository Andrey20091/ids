# =============================================================================
# Подавление шума Scapy на Windows без Npcap (чтение PCAP с диска не требует libpcap).
# =============================================================================
"""See: scapy/arch/windows/__init__.py sets conf.use_pcap = True then probes libpcap."""

from __future__ import annotations

import logging


_filter_installed = False


class _NoLibpcapProviderFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        if "No libpcap provider available" in msg:
            return False
        return True


def silence_windows_npcap_warning_if_needed() -> None:
    """
    Scapy на Windows при первом импорте ``scapy.arch`` пытается загрузить WinPcap/Npcap.
    Для офлайн-чтения ``PcapReader`` это не нужно — предупреждение только пугает.

    Вызывайте до любого ``import scapy.*`` в процессе (идемпотентно).
    """
    global _filter_installed
    if _filter_installed:
        return
    flt = _NoLibpcapProviderFilter()
    for name in ("scapy.loading", "scapy", "scapy.runtime"):
        logging.getLogger(name).addFilter(flt)
    _filter_installed = True
