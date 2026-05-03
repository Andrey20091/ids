# =============================================================================
# Многоуровневый каскад L1 → L2 (кейс 4): RF, IF, AE, LSTM, embedding-классификатор.
# =============================================================================
"""Cascade L1 → L2 and merge scores (ТЗ multi-level architecture)."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.pipeline.level1_filter import flow_level1_flags
from src.pipeline.level2_deep import (
    autoencoder_anomaly_score,
    embedding_classifier_attack_score,
    lstm_attack_score,
    random_forest_predict_proba,
    raw_header_cnn_attack_score,
)


def run_cascade(
    X_flow: pd.DataFrame,
    artifacts_dir: str | Path,
    flow_context: pd.DataFrame | None = None,
    timestamp_col: str | None = None,
    agg_freq: str = "1min",
    syn_multiplier: float = 3.0,
    use_rf: bool = True,
    use_ae: bool = False,
    use_lstm: bool = False,
    use_embedding: bool = True,
    use_header_cnn: bool = True,
    l2_only_after_l1: bool = True,
    packet_lstm_scores: pd.Series | None = None,
) -> pd.DataFrame:
    """
    Каскад L1 (SYN + IF на агрегатах) и L2 (RF, AE, LSTM, embedding).

    Параметры
    ----------
    X_flow : pd.DataFrame
        Числовые признаки потока (порядок строк совпадает с flow_context).
    artifacts_dir : str | Path
        Каталог с артефактами обучения.
    flow_context : pd.DataFrame | None
        Полный контекст потока (Timestamp, SYN, Protocol, Destination Port, …).
    timestamp_col : str | None
        Имя столбца времени для L1.
    use_embedding : bool
        Включить скоринг ``embedding_classifier.pt`` (если файлы есть).

    Возвращает
    -----------
    pd.DataFrame
        К столбцам линейки L1/L2 добавляются ``l2_emb_attack_score`` при наличии модели.
    """
    artifacts_dir = Path(artifacts_dir)
    out = pd.DataFrame(index=X_flow.index)

    # --- Уровень 1: быстрые правила по временным окнам ---
    if flow_context is not None and timestamp_col and timestamp_col in flow_context.columns:
        out["l1_triggered"] = flow_level1_flags(
            flow_context,
            timestamp_col,
            artifacts_dir,
            freq=agg_freq,
            syn_col_flow="SYN Flag Count",
            syn_multiplier=syn_multiplier,
        )
    else:
        out["l1_triggered"] = True

    l2_mask = out["l1_triggered"] if l2_only_after_l1 else pd.Series(True, index=out.index)

    X_num = X_flow.select_dtypes(include=["number"]).fillna(0)

    # --- L2: Random Forest ---
    out["l2_rf_attack_score"] = 0.0
    if use_rf and (artifacts_dir / "rf_model.joblib").is_file() and l2_mask.any():
        rf_full = random_forest_predict_proba(
            X_num,
            artifacts_dir / "rf_model.joblib",
            artifacts_dir / "rf_label_encoder.joblib",
        )
        out["l2_rf_attack_score"] = rf_full["l2_rf_attack_score"].where(l2_mask, 0.0)

    # --- L2: Autoencoder ---
    out["l2_ae_ratio"] = 0.0
    if use_ae and (artifacts_dir / "ae_model.pt").is_file() and l2_mask.any():
        ae_full = autoencoder_anomaly_score(X_num, artifacts_dir / "ae_model.pt")
        out["l2_ae_ratio"] = ae_full["l2_ae_ratio"].where(l2_mask, 0.0)
        if "l2_ae_mse" in ae_full.columns:
            out["l2_ae_mse"] = ae_full["l2_ae_mse"].where(l2_mask, 0.0)

    # --- L2: LSTM по окнам ---
    out["l2_lstm_attack_score"] = 0.0
    lstm_pt = artifacts_dir / "lstm_model.pt"
    lstm_le = artifacts_dir / "lstm_label_encoder.joblib"
    if use_lstm and lstm_pt.is_file() and lstm_le.is_file() and l2_mask.any():
        lstm_full = lstm_attack_score(X_num, lstm_pt, lstm_le)
        out["l2_lstm_attack_score"] = lstm_full["l2_lstm_attack_score"].where(l2_mask, 0.0)

    # --- L2: классификатор с embedding (порт + протокол + числа) ---
    out["l2_emb_attack_score"] = 0.0
    emb_ckpt = artifacts_dir / "embedding_classifier.pt"
    proto_e = artifacts_dir / "embedding_proto_encoder.joblib"
    port_e = artifacts_dir / "embedding_port_encoder.joblib"
    if (
        use_embedding
        and emb_ckpt.is_file()
        and proto_e.is_file()
        and port_e.is_file()
        and flow_context is not None
        and l2_mask.any()
    ):
        emb_full = embedding_classifier_attack_score(
            flow_context,
            emb_ckpt,
            proto_e,
            port_e,
        )
        out["l2_emb_attack_score"] = emb_full["l2_emb_attack_score"].where(l2_mask, 0.0)

    # --- L2: CNN по сырым байтам IP-заголовков (hb_*) ---
    out["l2_hdr_cnn_attack_score"] = 0.0
    hdr_ckpt = artifacts_dir / "raw_header_cnn.pt"
    hdr_le = artifacts_dir / "raw_header_cnn_label_encoder.joblib"
    if (
        use_header_cnn
        and hdr_ckpt.is_file()
        and hdr_le.is_file()
        and flow_context is not None
        and l2_mask.any()
    ):
        hdr_full = raw_header_cnn_attack_score(flow_context, hdr_ckpt, hdr_le)
        out["l2_hdr_cnn_attack_score"] = hdr_full["l2_hdr_cnn_attack_score"].where(l2_mask, 0.0)

    out["l2_lstm_pkt_score"] = 0.0
    if packet_lstm_scores is not None:
        pl = packet_lstm_scores.reindex(out.index).fillna(0.0)
        out["l2_lstm_pkt_score"] = pl.where(l2_mask, 0.0).astype(float)

    return out
