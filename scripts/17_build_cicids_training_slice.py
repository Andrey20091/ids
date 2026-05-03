# =============================================================================
# CICIDS2017: компактный CSV для prepare/train без загрузки всех дней в память (ТЗ).
# =============================================================================
"""Build a single labeled CSV from official day files (benign cap + attack rows per file)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

import pandas as pd

from src.ingest.cicids2017 import normalize_cicids2017_dataframe

_READ_CSV_KW = {"encoding": "utf-8", "encoding_errors": "replace", "low_memory": False}


def _collect_attack_rows(path: Path, cap: int, seed: int) -> pd.DataFrame:
    parts: list[pd.DataFrame] = []
    acc = 0
    for chunk in pd.read_csv(path, chunksize=80_000, **_READ_CSV_KW):
        chunk = normalize_cicids2017_dataframe(chunk)
        if "Label" not in chunk.columns:
            continue
        lab = chunk["Label"].astype(str).str.strip().str.upper()
        sub = chunk[lab != "BENIGN"]
        if sub.empty:
            continue
        need = cap - acc
        if need <= 0:
            break
        if len(sub) <= need:
            parts.append(sub)
            acc += len(sub)
        else:
            parts.append(sub.sample(n=need, random_state=seed))
            acc = cap
        if acc >= cap:
            break
    if not parts:
        return pd.DataFrame()
    return pd.concat(parts, ignore_index=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Собрать cicids2017_tz_slice.csv из TrafficLabelling: Monday (benign) + выборки атак."
    )
    parser.add_argument(
        "--output",
        type=str,
        default=str(_ROOT / "data/raw/cicids2017/cicids2017_tz_slice.csv"),
    )
    parser.add_argument(
        "--benign-csv",
        type=str,
        default=str(_ROOT / "TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv"),
    )
    parser.add_argument(
        "--benign-rows",
        type=int,
        default=35_000,
        help="Строк с начала benign-файла (Monday почти весь BENIGN).",
    )
    parser.add_argument(
        "--attack-csvs",
        nargs="*",
        default=[
            "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
            "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
            "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
            "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        ],
    )
    parser.add_argument("--attack-rows-each", type=int, default=6_000)
    parser.add_argument(
        "--attack-base",
        type=str,
        default=str(_ROOT / "TrafficLabelling"),
        help="Каталог для относительных имён в --attack-csvs (по умолчанию TrafficLabelling).",
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    benign_path = Path(args.benign_csv)
    if not benign_path.is_file():
        raise SystemExit(f"Benign CSV not found: {benign_path}")

    df_b = normalize_cicids2017_dataframe(
        pd.read_csv(benign_path, nrows=args.benign_rows, **_READ_CSV_KW)
    )
    print(f"Benign rows: {len(df_b)} from {benign_path.name}")

    attack_parts: list[pd.DataFrame] = []
    base = Path(args.attack_base)
    for name in args.attack_csvs:
        ap = Path(name)
        if not ap.is_file():
            ap = base / name
        if not ap.is_file():
            print(f"Skip missing: {name}")
            continue
        sub = _collect_attack_rows(ap, args.attack_rows_each, args.seed)
        print(f"  attacks from {ap.name}: {len(sub)}")
        if not sub.empty:
            attack_parts.append(sub)

    out_df = pd.concat([df_b, pd.concat(attack_parts, ignore_index=True)], ignore_index=True) if attack_parts else df_b

    outp = Path(args.output)
    outp = outp if outp.is_absolute() else _ROOT / outp
    outp.parent.mkdir(parents=True, exist_ok=True)
    out_df.to_csv(outp, index=False)
    print(f"Wrote {outp} shape={out_df.shape}")


if __name__ == "__main__":
    main()
