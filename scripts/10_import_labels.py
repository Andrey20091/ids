# =============================================================================
# Скрипт 10: импорт разметки (CSV/JSON) в storage/labels_dataset.csv
# =============================================================================
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.governance.storage import read_csv_rows, utc_now_iso, write_csv_rows


def _read_input(path: Path) -> list[dict]:
    if path.suffix.lower() == ".json":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []
    return read_csv_rows(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import labeled dataset rows from CSV/JSON")
    parser.add_argument("--input", required=True, help="Source CSV/JSON with labels")
    parser.add_argument("--output", default=str(_ROOT / "storage/labels_dataset.csv"))
    parser.add_argument("--source", default="imported")
    args = parser.parse_args()

    src = Path(args.input)
    if not src.is_absolute():
        src = _ROOT / src
    if not src.is_file():
        raise SystemExit(f"Input file not found: {src}")

    dst = Path(args.output)
    if not dst.is_absolute():
        dst = _ROOT / dst

    incoming = _read_input(src)
    if not incoming:
        raise SystemExit("No rows to import")

    existing = read_csv_rows(dst)
    by_id = {str(r.get("sample_id", "")): r for r in existing if str(r.get("sample_id", ""))}

    now = utc_now_iso()
    merged = 0
    added = 0
    for idx, row in enumerate(incoming):
        sample_id = str(row.get("sample_id", "")).strip() or f"smp_{src.stem}_{idx}"
        out = dict(row)
        out["sample_id"] = sample_id
        out["label_source"] = str(row.get("label_source", args.source))
        out["imported_at"] = now
        if sample_id in by_id:
            merged += 1
        else:
            added += 1
        by_id[sample_id] = out

    all_rows = list(by_id.values())
    keys = sorted({k for r in all_rows for k in r.keys()})
    write_csv_rows(dst, all_rows, keys)
    print(f"Labels import done: added={added}, merged={merged}, total={len(all_rows)} -> {dst}")


if __name__ == "__main__":
    main()

