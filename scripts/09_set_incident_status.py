# =============================================================================
# Скрипт 09: изменение статуса инцидента + аудит действия.
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

from src.governance.storage import append_jsonl, load_jsonl, upsert_jsonl, utc_now_iso

ALLOWED = {"new", "triaged", "in_progress", "waiting_approval", "closed_true", "closed_false"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Update incident status in incidents.jsonl")
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--status", required=True, choices=sorted(ALLOWED))
    parser.add_argument("--owner", default="")
    parser.add_argument("--comment", default="")
    parser.add_argument("--actor", default="cli_user")
    parser.add_argument("--incidents", default=str(_ROOT / "storage/incidents.jsonl"))
    parser.add_argument("--actions", default=str(_ROOT / "storage/incident_actions.jsonl"))
    args = parser.parse_args()

    inc_path = Path(args.incidents)
    if not inc_path.is_absolute():
        inc_path = _ROOT / inc_path
    act_path = Path(args.actions)
    if not act_path.is_absolute():
        act_path = _ROOT / act_path

    rows = load_jsonl(inc_path)
    target = None
    for r in rows:
        if str(r.get("incident_id", "")) == args.incident_id:
            target = r
            break
    if target is None:
        raise SystemExit(f"Incident not found: {args.incident_id}")

    old_status = str(target.get("status", ""))
    now = utc_now_iso()
    target["status"] = args.status
    target["updated_at"] = now
    if args.owner:
        target["owner"] = args.owner
    if args.comment:
        target["last_comment"] = args.comment
    upsert_jsonl(inc_path, [target], key="incident_id")

    action = {
        "action_id": f"act_{now.replace(':', '').replace('-', '').replace('T', '_').replace('Z', '')}",
        "incident_id": args.incident_id,
        "ts": now,
        "actor": args.actor,
        "action": "set_status",
        "old_value": old_status,
        "new_value": args.status,
        "comment": args.comment,
    }
    append_jsonl(act_path, action)
    print(f"Incident updated: {args.incident_id} {old_status} -> {args.status}")


if __name__ == "__main__":
    main()

