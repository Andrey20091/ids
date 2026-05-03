# =============================================================================
# PCAP + CSV (те же строки, что для prepare --input) → NPZ с сырыми байтами заголовков.
# Далее: python scripts/01_prepare_data.py --input <csv> --header-bytes-npz <npz>
# =============================================================================
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

from src.features.feature_config import header_byte_dim, load_merged_feature_config
from src.features.flow_key import flow_key_series
from src.ingest.cicids2017 import normalize_cicids2017_dataframe
from src.ingest.pcap_header_bytes import pcap_per_flow_header_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description="PCAP -> NPZ X (n_rows, D) for prepare --header-bytes-npz")
    parser.add_argument("--pcap", required=True, help="Входной PCAP")
    parser.add_argument(
        "--flows-csv",
        required=True,
        help="Same CSV as passed to 01_prepare --input (before or after column normalization)",
    )
    parser.add_argument("--output", default=str(_ROOT / "data/processed/header_bytes.npz"))
    parser.add_argument(
        "--features-yaml",
        default=str(_ROOT / "config/feature_columns.yaml"),
    )
    parser.add_argument(
        "--max-pcap-packets",
        type=int,
        default=0,
        help="0 = full PCAP; otherwise read at most N packets (faster on large files).",
    )
    args = parser.parse_args()
    feat_cfg = load_merged_feature_config(args.features_yaml)
    hb = feat_cfg.get("header_raw_bytes") or {}
    if not hb.get("enabled", False):
        raise SystemExit("В feature_columns.yaml header_raw_bytes.enabled должен быть true")
    max_p = int(hb.get("max_packets", 24))
    bpp = int(hb.get("bytes_per_packet", 40))
    D = header_byte_dim(feat_cfg)

    df = pd.read_csv(args.flows_csv, encoding="utf-8", encoding_errors="replace", low_memory=False)
    df = normalize_cicids2017_dataframe(df)
    if "flow_key" in df.columns:
        keys = df["flow_key"].astype(str).tolist()
    else:
        keys = flow_key_series(df).tolist()

    key_set = set(keys)
    cap = int(args.max_pcap_packets) if int(args.max_pcap_packets) > 0 else None
    tensors = pcap_per_flow_header_bytes(
        args.pcap,
        max_packets=max_p,
        bytes_per_packet=bpp,
        only_keys=key_set,
        max_read_packets=cap,
    )
    X = np.zeros((len(keys), D), dtype=np.uint8)
    for i, fk in enumerate(keys):
        mat = tensors.get(str(fk))
        if mat is not None:
            X[i] = mat.ravel()
    outp = Path(args.output)
    if not outp.is_absolute():
        outp = _ROOT / outp
    outp.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(outp, X=X)
    print(f"Wrote {outp} X.shape={X.shape} non_zero_bytes={int(X.sum())}")


if __name__ == "__main__":
    main()
