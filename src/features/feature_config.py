# =============================================================================
# Слияние списков признаков: кейс 4 + полный CICIDS2017 (ТЗ).
# =============================================================================
"""Load merged numeric feature list from feature_columns.yaml + canonical CICIDS."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from src.utils_config import project_root


def _canonical_numeric_path(features_yaml: Path) -> Path:
    local = features_yaml.parent / "cicids2017_canonical_numeric.yaml"
    if local.is_file():
        return local
    return project_root() / "config" / "cicids2017_canonical_numeric.yaml"


def load_merged_feature_config(features_yaml: str | Path) -> dict[str, Any]:
    """
    Загрузить ``feature_columns.yaml``; при ``cicids2017.include_all_canonical_numeric`` —
    объединить с ``cicids2017_canonical_numeric.yaml``; добавить ``hb_*`` при    ``header_raw_bytes.enabled``.
    """
    p = Path(features_yaml)
    with open(p, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    cfg = dict(cfg)
    merged: list[str] = list(cfg.get("numeric_features", []))
    seen: set[str] = set(merged)

    c17 = cfg.get("cicids2017") or {}
    if c17.get("include_all_canonical_numeric", False):
        canon_path = _canonical_numeric_path(p)
        with open(canon_path, encoding="utf-8") as f:
            canon = yaml.safe_load(f)
        canon_nums = list(canon.get("numeric_features", []))
        skip = set(c17.get("canonical_exclude", []))
        new_front: list[str] = []
        for c in canon_nums:
            if c in skip or c in seen:
                continue
            new_front.append(c)
            seen.add(c)
        merged = new_front + [c for c in merged if c not in seen]
        seen = set(merged)

    hb_cols = header_byte_columns(cfg)
    for c in hb_cols:
        if c not in seen:
            merged.append(c)
            seen.add(c)
    cfg["numeric_features"] = merged
    return cfg


def header_byte_dim(cfg: dict[str, Any]) -> int:
    hb = cfg.get("header_raw_bytes") or {}
    if not hb.get("enabled", False):
        return 0
    return int(hb.get("max_packets", 24)) * int(hb.get("bytes_per_packet", 40))


def header_byte_columns(cfg: dict[str, Any]) -> list[str]:
    d = header_byte_dim(cfg)
    if d <= 0:
        return []
    prefix = str((cfg.get("header_raw_bytes") or {}).get("column_prefix", "hb_"))
    return [f"{prefix}{i}" for i in range(d)]
