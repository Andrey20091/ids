# =============================================================================
# Метрики классификации и отчёты для отчёта по курсовой / валидации моделей.
# =============================================================================
"""Classification / anomaly metrics for coursework report."""

from __future__ import annotations

from sklearn.metrics import accuracy_score, classification_report, f1_score


def binary_metrics(y_true, y_pred) -> dict:
    """
    Бинарные метрики: accuracy, F1, доля ложных срабатываний (FPR), матрица ошибок.

    Параметры
    ----------
    y_true, y_pred
        Итерируемые последовательности меток 0/1.
    """
    y_true = list(y_true)
    y_pred = list(y_pred)
    tn = fp = fn = tp = 0
    for a, b in zip(y_true, y_pred):
        if a == 0 and b == 0:
            tn += 1
        elif a == 0 and b == 1:
            fp += 1
        elif a == 1 and b == 0:
            fn += 1
        else:
            tp += 1
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "fpr": float(fpr),
        "confusion_matrix": [[tn, fp], [fn, tp]],
    }


def full_classification_report(y_true, y_pred, labels=None) -> str:
    """Текстовый ``classification_report`` sklearn для вставки в отчёт."""
    return classification_report(y_true, y_pred, labels=labels)
