# =============================================================================
# Скрипт 14: переключение active модели в реестре.
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
    parser = argparse.ArgumentParser(description="Deploy approved model set as active")
    parser.add_argument("--model-set-id", required=True)
    parser.add_argument("--registry", default=str(_ROOT / "artifacts/model_registry.json"))
    args = parser.parse_args()

    p = Path(args.registry) if Path(args.registry).is_absolute() else (_ROOT / args.registry)
    reg = load_json(p, default={"active_model_set_id": "", "model_sets": []})
    target = None
    for m in reg.get("model_sets", []):
        if str(m.get("model_set_id")) == args.model_set_id:
            target = m
            break
    if target is None:
        raise SystemExit(f"Model set not found: {args.model_set_id}")
    if str(target.get("status", "")) not in {"approved", "production"}:
        raise SystemExit("Model set must be approved before deploy")

    reg["active_model_set_id"] = args.model_set_id
    now = utc_now_iso()
    for m in reg.get("model_sets", []):
        if str(m.get("model_set_id")) == args.model_set_id:
            m["status"] = "production"
            m["deployed_at"] = now
        elif m.get("status") == "production":
            m["status"] = "archived"
    save_json(p, reg)
    print(f"Deployed model set: {args.model_set_id}")


if __name__ == "__main__":
    main()

