from __future__ import annotations

import csv
import hashlib
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    if not path.is_file():
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, payload: Any) -> None:
    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    bad_rows = 0
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                bad_rows += 1
                continue
            if isinstance(row, dict):
                out.append(row)
    if bad_rows:
        warnings.warn(
            f"Skipped {bad_rows} malformed JSONL rows in {path}.",
            UserWarning,
            stacklevel=2,
        )
    return out


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    ensure_parent(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def upsert_jsonl(path: Path, rows: list[dict[str, Any]], key: str) -> tuple[int, int]:
    existing = load_jsonl(path)
    by_key: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for r in existing:
        k = str(r.get(key, ""))
        if not k:
            continue
        if k not in by_key:
            order.append(k)
        by_key[k] = r

    inserted = 0
    updated = 0
    for r in rows:
        k = str(r.get(key, ""))
        if not k:
            continue
        if k in by_key:
            updated += 1
        else:
            order.append(k)
            inserted += 1
        by_key[k] = r

    ensure_parent(path)
    with open(path, "w", encoding="utf-8") as f:
        for k in order:
            f.write(json.dumps(by_key[k], ensure_ascii=False) + "\n")
    return inserted, updated


def stable_alert_hash(alert: dict[str, Any]) -> str:
    payload = json.dumps(alert, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def read_csv_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def write_csv_rows(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    ensure_parent(path)
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

