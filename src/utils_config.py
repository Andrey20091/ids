# =============================================================================
# Загрузка YAML-конфигов относительно корня проекта.
# =============================================================================
"""Load YAML config relative to project root."""

from __future__ import annotations

import os
from pathlib import Path

import yaml


def project_root() -> Path:
    """Корень проекта: IDS_PROJECT_ROOT (frozen + AppData) или репозиторий (родитель ``src``)."""
    override = os.environ.get("IDS_PROJECT_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


def resolve_from_project_root(path_like: str | Path) -> Path:
    """Абсолютный путь: ``path_like`` или относительный к ``project_root()``."""
    p = Path(path_like)
    return p if p.is_absolute() else project_root() / p


def load_settings(path: str | Path | None = None) -> dict:
    """Прочитать ``config/settings.yaml`` или указанный путь."""
    p = resolve_from_project_root(path) if path else project_root() / "config" / "settings.yaml"
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)
