# =============================================================================
# Генерация расширенного корпоративного CSV для воспроизводимого prepare → train → detect.
# =============================================================================
"""Write data/raw/corporate_example/labeled_flows_e2e.csv (~150 rows, Timestamp spread)."""

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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--output",
        type=str,
        default=str(_ROOT / "data/raw/corporate_example/labeled_flows_e2e.csv"),
    )
    ap.add_argument("--rows", type=int, default=150)
    args = ap.parse_args()
    rng = np.random.default_rng(42)
    n = max(50, args.rows)
    base = pd.Timestamp("2025-01-21 08:00:00")
    rows: list[dict] = []
    for i in range(n):
        ts = base + pd.Timedelta(minutes=i // 4, seconds=i % 60)
        benign = rng.random() > 0.35
        label = "BENIGN" if benign else "Bot"
        uri = f"/api/v{i % 20}/resource?id={i}" if i % 3 == 0 else ""
        qname = "" if benign else f"{''.join(rng.choice(list('abcdefghijklmnopqrstuvwxyz0123456789'), size=48))}.evil.test"
        rows.append(
            {
                "Flow ID": i + 1,
                "Source IP": f"192.168.1.{10 + (i % 40)}",
                "Destination IP": "10.0.0.5" if benign else "203.0.113.7",
                "Protocol": 6 if i % 3 else 17,
                "Timestamp": ts.strftime("%d/%m/%Y %H:%M:%S"),
                "Label": label,
                "Flow Duration": float(rng.uniform(0.1, 12.0)),
                "Destination Port": int(rng.choice([443, 80, 8080, 4444, 53]) if not benign else 443),
                "Flow Bytes/s": float(rng.uniform(80, 130_000)),
                "Flow Packets/s": float(rng.uniform(1, 130)),
                "SYN Flag Count": float(rng.integers(0, 8)),
                "request_uri": uri,
                "dns_qname": qname if qname else "",
            }
        )
    df = pd.DataFrame(rows)
    outp = Path(args.output)
    outp.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(outp, index=False)
    print(f"Wrote {outp} ({len(df)} rows)")


if __name__ == "__main__":
    main()
