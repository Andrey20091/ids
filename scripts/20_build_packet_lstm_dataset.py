# =============================================================================
# Сборка NPZ датасета для LSTM по пакетам: PCAP + (опц.) выравнивание с flows CSV.
# =============================================================================
"""Usage: python scripts/20_build_packet_lstm_dataset.py --pcap x.pcap --flows-csv flows_raw.csv -o data/processed/packet_lstm_train.npz"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

import numpy as np
import pandas as pd

from src.features.feature_config import load_merged_feature_config
from src.ingest.cicids2017 import ensure_flow_schema_for_ml, normalize_cicids2017_dataframe
from src.ingest.pcap_packet_sequences import (
    DEFAULT_K,
    PACKET_FEATURE_DIM,
    align_sequences_to_flows_csv,
    extract_packet_sequences,
    flows_labels_binary,
)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--pcap", type=str, required=True)
    p.add_argument("--flows-csv", type=str, default="", help="Сырой CSV для выравнивания (CICIDS/корп); обязателен для y/flow_key")
    p.add_argument("-o", "--output", type=str, default=str(_ROOT / "data/processed/packet_lstm_train.npz"))
    p.add_argument("--k-packets", type=int, default=DEFAULT_K)
    p.add_argument("--max-pcap-packets", type=int, default=2_000_000)
    args = p.parse_args()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)

    seq = extract_packet_sequences(
        args.pcap,
        k_packets=int(args.k_packets),
        max_pcap_packets=int(args.max_pcap_packets),
    )
    if not seq:
        raise SystemExit("No packets / flows extracted from PCAP (empty or unsupported).")

    flows_path = Path(args.flows_csv) if args.flows_csv.strip() else None
    if not flows_path or not flows_path.is_file():
        raise SystemExit("--flows-csv required: same-day aligned export as PCAP for labels and keys.")

    feat_cfg = load_merged_feature_config(str(_ROOT / "config/feature_columns.yaml"))
    df = pd.read_csv(flows_path, encoding="utf-8", encoding_errors="replace", low_memory=False)
    df = normalize_cicids2017_dataframe(df)
    df = ensure_flow_schema_for_ml(df, feat_cfg)

    label_col = feat_cfg.get("label_column", "Label")
    fk_col = "flow_key"
    if fk_col not in df.columns:
        from src.features.flow_key import flow_key_series

        df[fk_col] = flow_key_series(df)

    X, mask = align_sequences_to_flows_csv(seq, df)
    y = flows_labels_binary(df, label_col)
    np.savez_compressed(
        out,
        X=X,
        y=y,
        mask=mask,
        k_packets=int(args.k_packets),
        feat_dim=PACKET_FEATURE_DIM,
        flow_keys=np.array(df[fk_col].astype(str)),
    )
    print(f"Wrote {out} shapes X={X.shape}, mask_true={mask.sum()} / {len(mask)}")


if __name__ == "__main__":
    main()
