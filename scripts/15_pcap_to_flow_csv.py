# =============================================================================
# PCAP → сырой CSV потоков (корпоративный трафик, ТЗ кейс 4).
# Далее: python main.py prepare --input <этот_csv>
# =============================================================================
"""Convert PCAP to CICIDS-like CSV (requires scapy)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.ingest.pcap_to_features import pcap_to_flow_dataframe


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP -> flow CSV (IP/TCP headers + aggregates)")
    parser.add_argument("--pcap", type=str, required=True, help="Входной .pcap / .pcapng")
    parser.add_argument(
        "--output",
        type=str,
        default=str(_ROOT / "data/raw/pcap_flows_raw.csv"),
        help="Выходной CSV для prepare",
    )
    args = parser.parse_args()
    df = pcap_to_flow_dataframe(args.pcap)
    sort_cols = [
        c        for c in (
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Protocol",
        )
        if c in df.columns
    ]
    if sort_cols:
        df = df.sort_values(sort_cols, kind="mergesort").reset_index(drop=True)
    outp = Path(args.output)
    outp = outp if outp.is_absolute() else _ROOT / outp
    outp.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(outp, index=False)
    print(f"Wrote {outp} rows={len(df)}")


if __name__ == "__main__":
    main()
