# =============================================================================
# Тесты: каскад ensemble без артефактов моделей (нулевые скоры L2).
# =============================================================================
"""Smoke test for cascade without artifact files."""

from __future__ import annotations

import pandas as pd

from src.pipeline.ensemble_orchestrator import run_cascade


def test_run_cascade_no_models(tmp_path):
    """``run_cascade`` с отключёнными моделями: только L1-флаги и нули по L2."""
    X = pd.DataFrame({"a": [1.0, 2.0], "b": [0.0, 1.0]})
    out = run_cascade(
        X,
        artifacts_dir=tmp_path,
        flow_context=None,
        use_rf=False,
        use_ae=False,
        use_lstm=False,
        use_embedding=False,
        use_header_cnn=False,
        l2_only_after_l1=False,
    )
    assert "l1_triggered" in out.columns
    assert out["l2_rf_attack_score"].eq(0.0).all()
    assert out["l2_hdr_cnn_attack_score"].eq(0.0).all()
