# =============================================================================
# Инварианты данных и consistency-check конфигурации пайплайна.
# =============================================================================
"""Validate prepared flows vs feature_columns; optional path checks for Settings."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pandas as pd


def deep_merge_models(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Глубокое слияние блоков моделей (training_profiles.development → models.*)."""
    out: dict[str, Any] = dict(base)
    for name, ov in overlay.items():
        cur = out.get(name)
        if isinstance(cur, dict) and isinstance(ov, dict):
            merged = dict(cur)
            merged.update(ov)
            out[name] = merged
        else:
            out[name] = ov
    return out


def apply_training_profile(settings: dict[str, Any], profile_name: str) -> dict[str, Any]:
    """
    Применить ``training_profiles.<name>`` к ``settings['models']`` (если секция есть).
    ``production`` или неизвестное имя — без изменений.
    """
    key = (profile_name or "").strip().lower()
    if key in ("", "production", "default"):
        return copy.deepcopy(settings)
    out = copy.deepcopy(settings)
    profiles = out.get("training_profiles") or {}
    overlay = profiles.get(key)
    if not overlay or not isinstance(overlay, dict):
        return out
    models = out.get("models") or {}
    out["models"] = deep_merge_models(models, overlay)
    return out


def validate_prepared_flows(df: pd.DataFrame, feat_cfg: dict[str, Any]) -> list[str]:
    """
    Проверки после prepare: наличие is_attack при Label, ненулевые hb_* если ожидались.

    Возвращает список предупреждений (пустой — всё ок).
    """
    warnings: list[str] = []
    label_col = feat_cfg.get("label_column", "Label")
    if label_col in df.columns and "is_attack" in df.columns:
        benign = df[label_col].astype(str).str.upper().eq("BENIGN")
        ia = df["is_attack"].apply(pd.to_numeric, errors="coerce").fillna(0).astype(int)
        bad = (benign & (ia != 0)) | ((~benign) & (ia != 1))
        if bad.any():
            warnings.append(
                "is_attack не согласован с Label (ожидалось: BENIGN→0, иначе→1). "
                f"Строк с ошибкой: {int(bad.sum())}."
            )
    elif label_col in df.columns and "is_attack" not in df.columns:
        warnings.append("Есть Label, но нет колонки is_attack — обучение embedding может быть недоступно.")

    from src.features.feature_config import header_byte_columns

    expected_hb = header_byte_columns(feat_cfg)
    if expected_hb:
        present = [c for c in expected_hb if c in df.columns]
        if len(present) != len(expected_hb):
            warnings.append(f"Ожидались колонки hb_* ({len(expected_hb)}), в данных меньше.")
        elif present:
            sub = df[present].apply(pd.to_numeric, errors="coerce").fillna(0.0)
            if float((sub.values**2).sum()) < 1e-12:
                warnings.append(
                    "Все hb_* равны нулю — CNN заголовков будет пропущен при train; "
                    "проверьте NPZ и scripts/16_build_header_byte_dataset.py + тот же день PCAP/CSV."
                )
    return warnings


def validate_settings_paths(root: Path, settings: dict[str, Any]) -> list[str]:
    """Проверить существование ключевых каталогов из paths (предупреждения, не fatal)."""
    warnings: list[str] = []
    paths = settings.get("paths") or {}
    for key in ("artifacts", "processed_data", "storage"):
        rel = paths.get(key)
        if not rel:
            continue
        p = Path(rel)
        full = (root / p) if not p.is_absolute() else p
        if not full.is_dir():
            warnings.append(f"paths.{key}: каталог отсутствует ({full}). Создайте или запустите prepare/train.")
    return warnings
