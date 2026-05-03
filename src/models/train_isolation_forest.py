# =============================================================================
# Обучение Isolation Forest: потоковые признаки и (отдельно) агрегаты по времени L1.
# =============================================================================
"""Isolation Forest training (ТЗ)."""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


def train_isolation_forest(
    X: pd.DataFrame,
    artifacts_dir: str | Path,
    n_estimators: int = 200,
    contamination: float = 0.02,
    random_state: int = 42,
    artifact_filename: str = "if_model.joblib",
) -> dict:
    """
    Обучить IF на матрице признаков (без меток) и сохранить в artifacts_dir.

    Параметры
    ----------
    X : pd.DataFrame
        Числовые признаки (потоки или агрегаты по окнам).
    artifacts_dir : str | Path
        Каталог для if_model.joblib / if_model_agg.joblib.
    artifact_filename : str
        Имя файла (для потоков — if_model.joblib, для L1-агрегатов — if_model_agg.joblib).

    Возвращает
    -----------
    dict
        Путь к сохранённой модели.
    """
    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)
    out_path = artifacts_dir / artifact_filename
    joblib.dump(model, out_path)
    return {"model_path": str(out_path)}
