# =============================================================================
# Быстрая самопроверка: пути конфига, flows.csv, наличие RF после prepare.
# =============================================================================
"""CLI: python scripts/validate_project_state.py или main.py validate"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
_ROOT = Path(os.environ["IDS_PROJECT_ROOT"]) if os.environ.get("IDS_PROJECT_ROOT") else _bundle
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

import pandas as pd
import yaml

from src.features.feature_config import load_merged_feature_config
from src.utils.pipeline_validate import validate_prepared_flows, validate_settings_paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Проверка конфигурации и инвариантов flows.csv")
    parser.add_argument(
        "--flows-rows",
        type=int,
        default=8000,
        help="Сколько строк flows.csv прочитать для проверки is_attack/hb_* (0 = только заголовки).",
    )
    args = parser.parse_args()

    cfg_path = _ROOT / "config/settings.yaml"
    feat_path = _ROOT / "config/feature_columns.yaml"
    if not cfg_path.is_file():
        print(f"Ошибка: нет {cfg_path}")
        return 2

    with open(cfg_path, encoding="utf-8") as f:
        settings = yaml.safe_load(f)

    for w in validate_settings_paths(_ROOT, settings):
        print(f"Предупреждение: {w}")

    try:
        feat_cfg = load_merged_feature_config(feat_path)
    except Exception as e:
        print(f"Ошибка загрузки feature_columns: {e}")
        return 2

    paths = settings.get("paths") or {}
    proc = paths.get("processed_data", "data/processed")
    flows = (_ROOT / proc / "flows.csv").resolve()
    if not flows.is_file():
        print(f"Нет flows.csv по пути {flows} — выполните prepare.")
        return 1

    nrows = args.flows_rows
    if nrows <= 0:
        nrows = 1
    df = pd.read_csv(flows, encoding="utf-8", encoding_errors="replace", nrows=nrows, low_memory=False)
    for msg in validate_prepared_flows(df, feat_cfg):
        print(f"Предупреждение (flows): {msg}")

    art_rel = paths.get("artifacts", "artifacts")
    art = (_ROOT / art_rel).resolve()
    rf = art / "rf_model.joblib"
    if not rf.is_file():
        print(f"Нет {rf} — после prepare запустите: python scripts/02_train_all.py")
        return 1

    print("Состояние проекта: ок (flows + rf_model найдены).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
