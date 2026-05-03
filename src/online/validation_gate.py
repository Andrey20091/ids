# =============================================================================
# Валидационный шлюз: метрики F1 / precision / recall перед принятием модели.
# =============================================================================
"""Validation gate before accepting new models (ТЗ)."""

from __future__ import annotations

from sklearn.metrics import f1_score, precision_score, recall_score


def simple_validation_f1(y_true, y_pred) -> dict:
    """
    Сводка метрик для бинарных предсказаний (например IF vs ``is_attack``).

    Параметры
    ----------
    y_true, y_pred
        Векторы истинных меток и предсказаний (0/1).
    """
    return {
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
    }
