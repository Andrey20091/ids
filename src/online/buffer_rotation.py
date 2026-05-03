# =============================================================================
# Версия online-буфера (инкремент при ротации / maintain) для согласования с watermark.
# =============================================================================
from __future__ import annotations

import json
from pathlib import Path

from src.governance.storage import utc_now_iso


def buffer_meta_path(buffer_csv: Path) -> Path:
    """Рядом с CSV: для flows_online_buffer.csv -> .flows_online_buffer.meta.json"""
    p = Path(buffer_csv)
    return p.parent / f".{p.stem}.meta.json"


def read_rotation_generation(buffer_csv: Path) -> int:
    """Текущее поколение буфера; без meta-файла считается 0."""
    mp = buffer_meta_path(buffer_csv)
    if not mp.is_file():
        return 0
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
        return max(0, int(data.get("rotation_generation", 0) or 0))
    except Exception:
        return 0


def increment_rotation_generation(buffer_csv: Path) -> int:
    """После успешной ротации или compact: +1 к generation, вернуть новое значение."""
    mp = buffer_meta_path(buffer_csv)
    prev_data: dict = {}
    if mp.is_file():
        try:
            prev_data = json.loads(mp.read_text(encoding="utf-8"))
            if not isinstance(prev_data, dict):
                prev_data = {}
        except Exception:
            prev_data = {}
    prev = max(0, int(prev_data.get("rotation_generation", 0) or 0))
    nxt = prev + 1
    prev_data.update(
        {
            "rotation_generation": nxt,
            "updated_at": utc_now_iso(),
            "buffer_csv": str(Path(buffer_csv).resolve()),
        }
    )
    mp.parent.mkdir(parents=True, exist_ok=True)
    mp.write_text(json.dumps(prev_data, ensure_ascii=False, indent=2), encoding="utf-8")
    return nxt
