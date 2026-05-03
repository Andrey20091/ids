# =============================================================================
# Онлайн-цикл: один шаг дообучения IF или бесконечный цикл каждые N минут (ТЗ).
# =============================================================================
"""One retrain iteration or sleep loop (ТЗ: 15 min)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_bundle = Path(__file__).resolve().parents[1]
if str(_bundle) not in sys.path:
    sys.path.insert(0, str(_bundle))

from src.utils_config import load_settings, project_root

_ROOT = project_root()


def main() -> None:
    """Один прогон дообучения или цикл ``--loop`` с интервалом из settings."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=str, default=str(_ROOT / "data/processed/flows.csv"))
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Run forever every N minutes (default first iteration runs immediately).",
    )
    parser.add_argument(
        "--delayed-first-tick",
        action="store_true",
        help="In loop mode, wait interval before first iteration.",
    )
    args = parser.parse_args()

    try:
        settings = load_settings() or {}
    except Exception as e:
        raise SystemExit(f"Ошибка чтения config/settings.yaml ({_ROOT / 'config/settings.yaml'}): {e}") from e
    online_cfg = settings.get("online", {})
    if not isinstance(online_cfg, dict) or "retrain_interval_minutes" not in online_cfg:
        raise SystemExit(
            f"Некорректный config/settings.yaml: отсутствует online.retrain_interval_minutes ({_ROOT / 'config/settings.yaml'})."
        )
    try:
        minutes = int(online_cfg["retrain_interval_minutes"])
    except (TypeError, ValueError) as e:
        raise SystemExit(
            f"Некорректный online.retrain_interval_minutes: {online_cfg.get('retrain_interval_minutes')!r}"
        ) from e
    if minutes < 0:
        raise SystemExit("online.retrain_interval_minutes должен быть >= 0.")

    from src.online.retrain_scheduler import run_one_retrain_iteration, sleep_loop

    def job():
        print(run_one_retrain_iteration(args.data))

    if args.loop:
        sleep_loop(minutes, job, max_iterations=None, initial_delay=args.delayed_first_tick)
    else:
        job()


if __name__ == "__main__":
    main()
