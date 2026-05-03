# =============================================================================
# Валидация колонок корпоративного размеченного CSV перед prepare.
# =============================================================================
"""Usage: python scripts/validate_corporate_csv.py --input data/raw/your_export.csv"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.ingest.load_corporate import load_corporate_table, validate_corporate_labeled_csv


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate corporate labeled flow CSV")
    parser.add_argument("--input", type=str, required=True)
    parser.add_argument(
        "--strict-timestamp",
        action="store_true",
        help="Считать отсутствие Timestamp ошибкой",
    )
    args = parser.parse_args()
    df = load_corporate_table(args.input, encoding="utf-8", encoding_errors="replace", low_memory=False)
    err, warn = validate_corporate_labeled_csv(df, strict_timestamp=args.strict_timestamp)
    for w in warn:
        print(f"Предупреждение: {w}")
    for e in err:
        print(f"Ошибка: {e}")
    if err:
        print("Исправьте CSV или расширьте схему до совместимости с CICIDS-подобными колонками.")
        return 1
    print(f"OK: {len(df)} rows, columns include Label and flow endpoints.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
