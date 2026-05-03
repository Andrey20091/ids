# =============================================================================
# Проверка установленных пакетов перед запуском пайплайна.
# =============================================================================
"""Проверка окружения: зависимости и импорты (до запуска пайплайна)."""

from __future__ import annotations

from importlib.util import find_spec
import sys


def _module_available(module_name: str) -> bool:
    return find_spec(module_name) is not None


def main() -> int:
    """Проверить импорты core/streamlit/plotly; torch опционален."""
    missing = []
    optional_missing = []
    print("Проверка окружения: core-зависимости...", flush=True)
    for mod in ("pandas", "numpy", "yaml", "sklearn", "joblib"):
        if not _module_available(mod):
            missing.append(mod)

    frozen = getattr(sys, "frozen", False)
    if frozen:
        print(
            "Проверка окружения: дашборд — отдельное приложение IDS Dashboard (Streamlit в CLI не требуется).",
            flush=True,
        )
    else:
        print("Проверка окружения: dashboard-зависимости...", flush=True)
        if not _module_available("streamlit"):
            optional_missing.append("streamlit (для дашборда)")
        if not _module_available("plotly"):
            optional_missing.append("plotly (для дашборда)")

    if missing:
        print("Не хватает пакетов:", ", ".join(missing))
        print("Активируйте venv и выполните: pip install -r requirements.txt")
        return 1
    if optional_missing:
        print("Предупреждение: не хватает пакетов дашборда:", ", ".join(optional_missing))
        print("Для дашборда выполните: pip install -r requirements.txt")

    if not _module_available("torch"):
        print("Примечание: torch не установлен — используйте scripts/02_train_all.py --skip-torch")
    else:
        print("torch: импортируется в текущем интерпретаторе (для train/deep-моделей).")

    print(f"Интерпретатор: {sys.executable}")
    print("Подсказка: запускайте main.py через тот же venv, где pip install -r requirements*.txt")
    print("Окружение в порядке.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
