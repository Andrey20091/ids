# =============================================================================
# Обучение Random Forest по числовым признакам потоков (кейс 4, L2).
# =============================================================================
"""Random Forest training (ТЗ)."""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


def train_random_forest(
    X: pd.DataFrame,
    y: pd.Series,
    artifacts_dir: str | Path,
    n_estimators: int = 200,
    max_depth: int | None = 24,
    random_state: int = 42,
    test_size: float = 0.2,
) -> dict:
    """Train RF classifier; save model, label encoder, and report accuracy."""
    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    n_samples = len(X)
    if n_samples < 2:
        raise ValueError(
            "RandomForest training requires at least 2 rows after prepare; "
            f"got {n_samples}."
        )

    le = LabelEncoder()
    y_enc = le.fit_transform(y.astype(str))

    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_enc, test_size=test_size, random_state=random_state, stratify=y_enc
        )
    except ValueError:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_enc, test_size=test_size, random_state=random_state
        )

    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    acc = float(clf.score(X_test, y_test))

    joblib.dump(clf, artifacts_dir / "rf_model.joblib")
    joblib.dump(le, artifacts_dir / "rf_label_encoder.joblib")

    return {"accuracy": acc, "model_path": str(artifacts_dir / "rf_model.joblib")}
