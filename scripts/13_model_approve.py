# =============================================================================
# Скрипт 13: утверждение candidate модели (approval)
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

from src.governance.storage import load_json, save_json, utc_now_iso


def main() -> None:
    parser = argparse.ArgumentParser(description="Approve model set in model_registry.json")
    parser.add_argument("--model-set-id", required=True)
    parser.add_argument("--approved-by", default="cli_user")
    parser.add_argument("--registry", default=str(_ROOT / "artifacts/model_registry.json"))
    args = parser.parse_args()

    p = Path(args.registry) if Path(args.registry).is_absolute() else (_ROOT / args.registry)
    reg = load_json(p, default={"active_model_set_id": "", "model_sets": []})
    found = False
    for m in reg.get("model_sets", []):
        if str(m.get("model_set_id")) == args.model_set_id:
            m["status"] = "approved"
            m["approved_by"] = args.approved_by
            m["approved_at"] = utc_now_iso()
            found = True
    if not found:
        raise SystemExit(f"Model set not found: {args.model_set_id}")
    save_json(p, reg)
    print(f"Approved model set: {args.model_set_id}")


if __name__ == "__main__":
    main()

