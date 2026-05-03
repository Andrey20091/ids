# =============================================================================
# Скрипт 11: печать последних записей истории online/retrain.
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

from src.governance.storage import load_jsonl


def main() -> None:
    parser = argparse.ArgumentParser(description="Show latest retrain history entries")
    parser.add_argument("--path", default=str(_ROOT / "storage/retrain_history.jsonl"))
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    p = Path(args.path)
    if not p.is_absolute():
        p = _ROOT / p
    rows = load_jsonl(p)
    if not rows:
        print(f"No retrain history at {p}")
        return

    for r in rows[-max(args.limit, 1) :]:
        print(
            f"{r.get('ts', '?')} run={r.get('run_id', '?')} status={r.get('result', '?')} "
            f"reason={r.get('reason', '')}"
        )


if __name__ == "__main__":
    main()

