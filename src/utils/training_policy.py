from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from src.utils_config import project_root, resolve_from_project_root


def get_training_policy(settings: dict[str, Any]) -> dict[str, Any]:
    raw = settings.get("training_policy", {}) if isinstance(settings, dict) else {}
    if not isinstance(raw, dict):
        raw = {}
    return {
        "enforce_cicids_baseline": bool(raw.get("enforce_cicids_baseline", False)),
        "require_baseline_before_online": bool(raw.get("require_baseline_before_online", False)),
        "prohibit_full_retrain_on_new_data": bool(raw.get("prohibit_full_retrain_on_new_data", False)),
        "cicids_tag_values": [str(x).strip().lower() for x in (raw.get("cicids_tag_values") or ["cicids2017"]) if str(x).strip()],
        "baseline_manifest_path": str(raw.get("baseline_manifest_path", "storage/baseline_manifest.json")),
        "allow_force_rebaseline": bool(raw.get("allow_force_rebaseline", False)),
        "disallow_skip_torch_for_baseline": bool(raw.get("disallow_skip_torch_for_baseline", False)),
    }


def normalize_dataset_tag(tag: str | None) -> str:
    return str(tag or "").strip().lower()


def is_cicids_tag(tag: str | None, policy: dict[str, Any]) -> bool:
    t = normalize_dataset_tag(tag)
    return bool(t) and t in set(policy.get("cicids_tag_values", []))


def baseline_manifest_path(settings: dict[str, Any], base: Path | None = None) -> Path:
    root = base or project_root()
    pol = get_training_policy(settings)
    return resolve_from_project_root(pol["baseline_manifest_path"]) if base is None else (
        Path(pol["baseline_manifest_path"]) if Path(pol["baseline_manifest_path"]).is_absolute() else root / pol["baseline_manifest_path"]
    )


def _file_sha256(path: Path) -> str:
    h = sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def build_artifact_manifest_entries(artifact_paths: list[Path]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in artifact_paths:
        if not p.is_file():
            continue
        st = p.stat()
        out.append(
            {
                "path": str(p),
                "size_bytes": int(st.st_size),
                "mtime": float(st.st_mtime),
                "sha256": _file_sha256(p),
            }
        )
    return out


def write_baseline_manifest(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def read_baseline_manifest(path: Path) -> tuple[dict[str, Any] | None, str]:
    if not path.is_file():
        return None, f"baseline manifest not found: {path}"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return None, f"baseline manifest is invalid json: {e}"
    if not isinstance(payload, dict):
        return None, "baseline manifest has invalid root type"
    if not payload.get("dataset_tag"):
        return None, "baseline manifest missing dataset_tag"
    return payload, ""
