"""L1 IF: явное предупреждение при несовпадении признаков модели и агрегатов."""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
import pytest
from sklearn.ensemble import IsolationForest

from src.pipeline.level1_filter import level1_scores


class _ModelWithoutFeatureNames:
    def predict(self, _x):
        raise ValueError("shape mismatch")


def test_level1_scores_warns_when_if_trained_on_different_columns(tmp_path: Path) -> None:
    """Модель на колонках (a,b) не применима к матрице агрегатов — должно быть предупреждение, не silent fail."""
    X_fit = pd.DataFrame({"a": [0.0, 1.0, 2.0, 4.0], "b": [1.0, 1.0, 2.0, 0.0]})
    m = IsolationForest(n_estimators=8, random_state=0)
    m.fit(X_fit)
    model_path = tmp_path / "if_flow.joblib"
    joblib.dump(m, model_path)

    X_agg = pd.DataFrame({"Flow_Packets_s": [10.0, 20.0, 30.0], "SYN_Flag_Count": [0.0, 1.0, 2.0]})
    with pytest.warns(UserWarning, match="L1 IsolationForest"):
        out = level1_scores(
            X_agg,
            if_model_path=model_path,
            syn_col="SYN_Flag_Count",
            syn_multiplier=10.0,
        )
    assert out["l1_if_anomaly"].eq(False).all()


def test_level1_scores_warns_when_predict_valueerror(tmp_path: Path) -> None:
    """Если модель без feature_names падает на predict, это должно быть наблюдаемо (warning)."""
    model_path = tmp_path / "if_bad.joblib"
    joblib.dump(_ModelWithoutFeatureNames(), model_path)
    X_agg = pd.DataFrame({"Flow_Packets_s": [10.0, 20.0], "SYN_Flag_Count": [1.0, 2.0]})
    with pytest.warns(UserWarning, match="не удалось применить модель"):
        out = level1_scores(X_agg, if_model_path=model_path, syn_col="SYN_Flag_Count")
    assert out["l1_if_anomaly"].eq(False).all()


def test_level1_scores_warns_when_model_load_fails(tmp_path: Path, monkeypatch) -> None:
    """Сбой загрузки joblib не должен ронять detect-path: warning + fallback."""
    model_path = tmp_path / "if_broken.joblib"
    model_path.write_bytes(b"x")
    X_agg = pd.DataFrame({"Flow_Packets_s": [10.0, 20.0], "SYN_Flag_Count": [0.0, 100.0]})

    def _boom(_path):
        raise MemoryError("simulated OOM during model load")

    monkeypatch.setattr(joblib, "load", _boom)
    with pytest.warns(UserWarning, match="не удалось загрузить модель"):
        out = level1_scores(X_agg, if_model_path=model_path, syn_col="SYN_Flag_Count")
    assert out["l1_if_anomaly"].eq(False).all()
