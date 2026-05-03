# =============================================================================
# Обучение lstm_packets_model.pt по NPZ из скрипта 20.
# =============================================================================
"""python scripts/21_train_packet_lstm.py --dataset data/processed/packet_lstm_train.npz"""

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
import yaml

from src.models.train_lstm_packets import infer_lstm_packets, train_lstm_packets


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", type=str, required=True)
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--hidden", type=int, default=64)
    args = ap.parse_args()

    blob = np.load(args.dataset, allow_pickle=True)
    X = blob["X"]
    y = blob["y"]
    mask = blob["mask"]
    with open(_ROOT / "config/settings.yaml", encoding="utf-8") as f:
        settings = yaml.safe_load(f)
    art = _ROOT / settings["paths"]["artifacts"]
    info = train_lstm_packets(
        X,
        y,
        mask,
        artifacts_dir=art,
        epochs=args.epochs,
        hidden_size=args.hidden,
    )
    print(info)
    # сохранить скоры для строк датасета — удобно для смоук-detect без повторного PCAP
    probs = infer_lstm_packets(X, Path(art) / "lstm_packets_model.pt")
    outp = _ROOT / "data/processed/packet_lstm_scores.npz"
    outp.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        outp,
        flow_keys=np.array(blob["flow_keys"]),
        scores=probs.astype(np.float32),
        mask=np.array(mask),
    )
    print(f"Scores NPZ (--packet-lstm-scores): {outp.resolve()}")


if __name__ == "__main__":
    main()
