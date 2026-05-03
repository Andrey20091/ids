# =============================================================================
# Скрипт 00: генерация синтетического CSV в стиле CICIDS2017 + колонки кейса 4
# (HTTP URI, DNS QNAME) для демонстрации L2-признаков без внешних данных.
# Зависимости: только стандартная библиотека.
# =============================================================================
"""
Синтетический CSV в формате CICIDS (имена колонок как в config/feature_columns.yaml).

Usage:
  python scripts/00_generate_demo_data.py
  python scripts/00_generate_demo_data.py --rows 8000 --output data/raw/synthetic_cicids_demo.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import string
from datetime import datetime, timedelta
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle


def _random_subdomain(n: int) -> str:
    """Случайная метка поддомена для имитации DNS-запроса."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choices(alphabet, k=n))


def _dns_qname(benign: bool) -> str:
    """
    Сформировать похожее на QNAME имя: короткое для BENIGN, длинное/шумное для атак (туннель).
    """
    if benign:
        return f"{_random_subdomain(4)}.example.com."
    # Имитация подозрительно длинного энтропийного имени
    return ".".join(_random_subdomain(random.randint(8, 16)) for _ in range(4)) + ".tld."


def _http_uri(benign: bool) -> str:
    """Простой путь HTTP: короткий нормальный или длинный для аномалии."""
    if benign:
        return random.choice(["/index.html", "/api/health", "/static/logo.png"])
    return "/search?q=" + "".join(random.choices(string.ascii_letters + string.digits, k=120))


def main() -> None:
    """Парсинг аргументов и запись CSV с потоками и полями под кейс 4."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=8000)
    parser.add_argument(
        "--output",
        type=str,
        default=str(_ROOT / "data/raw/synthetic_cicids_demo.csv"),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Seed для воспроизводимой генерации (по умолчанию: 42).",
    )
    parser.add_argument(
        "--random-seed",
        action="store_true",
        help="Игнорировать --seed и использовать системную энтропию (каждый запуск разный).",
    )
    parser.add_argument(
        "--include-hb",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Добавить синтетические hb_* колонки (по умолчанию включено, отключить: --no-include-hb).",
    )
    parser.add_argument(
        "--hb-dim",
        type=int,
        default=960,
        help="Число hb_* колонок (по умолчанию: 960).",
    )
    parser.add_argument(
        "--hb-zero-prob-benign",
        type=float,
        default=0.7,
        help="Вероятность нуля для hb_* у BENIGN (0..1).",
    )
    parser.add_argument(
        "--hb-zero-prob-attack",
        type=float,
        default=0.35,
        help="Вероятность нуля для hb_* у атак (0..1).",
    )
    args = parser.parse_args()

    outp = Path(args.output)
    outp.parent.mkdir(parents=True, exist_ok=True)
    seed_used = None if args.random_seed else int(args.seed)
    random.seed(seed_used)

    # --- Набор колонок: базовый CICIDS + HTTP/DNS для обогащения L2 ---
    cols = [
        "Timestamp",
        "Source IP",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Bwd Packet Length Max",
        "Flow Bytes/s",
        "Flow Packets/s",
        "SYN Flag Count",
        "FIN Flag Count",
        "RST Flag Count",
        "Protocol",
        "Destination Port",
        "http_request_uri",
        "dns_qname",
        "Label",
    ]
    hb_dim = max(0, int(args.hb_dim))
    hb_cols = [f"hb_{i}" for i in range(hb_dim)] if bool(args.include_hb) else []
    cols.extend(hb_cols)

    base = datetime(2017, 7, 3, 9, 0, 0)
    with open(outp, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for i in range(args.rows):
            benign = random.random() < 0.72
            if benign:
                label = "BENIGN"
                syn = random.randint(0, 2)
                dur = random.uniform(0.001, 120.0)
                fps = random.uniform(0.1, 50.0)
                src = f"10.0.{random.randint(0, 5)}.{random.randint(1, 200)}"
            else:
                label = random.choice(["PortScan", "DoS Hulk", "FTP-Patator"])
                syn = random.randint(5, 400)
                dur = random.uniform(0.001, 30.0)
                fps = random.uniform(10.0, 5000.0)
                src = f"192.168.{random.randint(0, 3)}.{random.randint(1, 250)}"

            ts = base + timedelta(seconds=i * 3 + random.randint(0, 2))
            row = {
                "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "Source IP": src,
                "Flow Duration": f"{dur:.6f}",
                "Total Fwd Packets": str(random.randint(1, 500)),
                "Total Backward Packets": str(random.randint(0, 500)),
                "Fwd Packet Length Max": str(random.randint(0, 1500)),
                "Fwd Packet Length Min": str(random.randint(0, 100)),
                "Fwd Packet Length Mean": str(random.uniform(0, 500)),
                "Bwd Packet Length Max": str(random.randint(0, 1500)),
                "Flow Bytes/s": str(random.uniform(100, 1e6)),
                "Flow Packets/s": f"{fps:.6f}",
                "SYN Flag Count": str(syn),
                "FIN Flag Count": str(random.randint(0, 3)),
                "RST Flag Count": str(random.randint(0, 5)),
                "Protocol": str(random.choice([6, 17, 6, 6])),
                "Destination Port": str(random.choice([80, 443, 22, 8080, 53])),
                "http_request_uri": _http_uri(benign),
                "dns_qname": _dns_qname(benign),
                "Label": label,
            }
            if hb_cols:
                zero_prob = float(args.hb_zero_prob_benign if benign else args.hb_zero_prob_attack)
                zero_prob = min(1.0, max(0.0, zero_prob))
                for c in hb_cols:
                    if random.random() < zero_prob:
                        row[c] = "0"
                    else:
                        # У атак чаще выше амплитуда синтетического "header signal"
                        if benign:
                            row[c] = str(random.randint(1, 96))
                        else:
                            row[c] = str(random.randint(32, 255))
            w.writerow(row)

    if seed_used is None:
        print(f"Wrote {args.rows} rows to {outp} (seed=random)")
    else:
        print(f"Wrote {args.rows} rows to {outp} (seed={seed_used})")


if __name__ == "__main__":
    main()
