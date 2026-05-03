# =============================================================================
# Уровень 2: скоринг RF, AE, LSTM и классификатора с embedding (кейс 4).
# =============================================================================
"""Level 2: RF / AE / LSTM / embedding scoring hooks (ТЗ)."""

from __future__ import annotations

from pathlib import Path
import warnings

import joblib
import numpy as np
import pandas as pd

try:
    import torch
except ImportError:
    torch = None


def _torch_load(path: str | Path):
    if torch is None:
        raise ImportError("torch required")
    try:
        return torch.load(path, map_location="cpu", weights_only=False)
    except TypeError:
        return torch.load(path, map_location="cpu")


def random_forest_predict_proba(
    X: pd.DataFrame,
    model_path: str | Path,
    label_encoder_path: str | Path,
) -> pd.DataFrame:
    """Return max attack probability per row (1 - prob of benign if class 'BENIGN' exists)."""
    clf = joblib.load(model_path)
    le = joblib.load(label_encoder_path)
    proba = clf.predict_proba(X.fillna(0))
    classes = list(getattr(le, "classes_", []))
    if len(classes) != proba.shape[1]:
        try:
            classes = [str(x) for x in le.inverse_transform(clf.classes_)]
        except Exception:
            classes = [str(x) for x in getattr(clf, "classes_", list(range(proba.shape[1])))]
            warnings.warn(
                "RF label encoder and model classes mismatch; using classifier classes fallback.",
                UserWarning,
                stacklevel=2,
            )
    benign_idx = None
    for i, c in enumerate(classes):
        if str(c).upper() == "BENIGN":
            benign_idx = i
            break
    if benign_idx is None:
        attack_score = proba.max(axis=1)
    else:
        attack_score = 1.0 - proba[:, benign_idx]
    return pd.DataFrame({"l2_rf_attack_score": attack_score}, index=X.index)


def autoencoder_anomaly_score(
    X: pd.DataFrame,
    ae_checkpoint_path: str | Path,
) -> pd.DataFrame:
    """Reconstruction MSE vs saved threshold (higher = more anomalous)."""
    if torch is None:
        return pd.DataFrame({"l2_ae_ratio": 0.0}, index=X.index)

    from src.models.train_autoencoder import _AE

    ckpt = _torch_load(ae_checkpoint_path)
    n_features = ckpt["n_features"]
    encoding_dim = ckpt["encoding_dim"]
    threshold = ckpt["threshold"]
    model = _AE(n_features, encoding_dim=encoding_dim)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    Xa = X.iloc[:, :n_features].astype(np.float32).values
    with torch.no_grad():
        t = torch.from_numpy(Xa)
        recon = model(t)
        mse = ((recon.numpy() - Xa) ** 2).mean(axis=1)
    ratio = mse / (threshold + 1e-9)
    return pd.DataFrame({"l2_ae_ratio": ratio, "l2_ae_mse": mse}, index=X.index)


def lstm_attack_score(
    X: pd.DataFrame,
    lstm_checkpoint_path: str | Path,
    label_encoder_path: str | Path,
    sequence_length: int | None = None,
) -> pd.DataFrame:
    """
    Sequence classifier trained on sliding windows; score = 1 - P(benign) at end of each window.
    First (sequence_length - 1) rows get score 0.0 (no full window yet).
    """
    if torch is None:
        return pd.DataFrame({"l2_lstm_attack_score": 0.0}, index=X.index)

    from src.models.train_lstm import _LSTMClassifier

    ckpt = _torch_load(lstm_checkpoint_path)
    seq_len = int(sequence_length or ckpt["sequence_length"])
    n_features = int(ckpt["n_features"])
    hidden_size = int(ckpt["hidden_size"])
    num_classes = int(ckpt["num_classes"])

    le = joblib.load(label_encoder_path)
    classes = list(le.classes_)
    benign_idx = None
    for i, c in enumerate(classes):
        if str(c).upper() == "BENIGN":
            benign_idx = i
            break

    model = _LSTMClassifier(n_features, hidden_size, num_classes)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    Xa = X.astype(np.float32).values
    n = len(Xa)
    scores = np.zeros(n, dtype=np.float64)
    if n < seq_len:
        return pd.DataFrame({"l2_lstm_attack_score": scores}, index=X.index)

    stacks = np.stack([Xa[i : i + seq_len] for i in range(0, n - seq_len + 1)], axis=0).astype(np.float32)
    with torch.no_grad():
        logits = model(torch.from_numpy(stacks)).numpy()
        proba = _softmax(logits)
        if benign_idx is None:
            attack = proba.max(axis=1)
        else:
            attack = 1.0 - proba[:, benign_idx]
    scores[seq_len - 1 :] = attack

    return pd.DataFrame({"l2_lstm_attack_score": scores}, index=X.index)


def _softmax(z: np.ndarray) -> np.ndarray:
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / e.sum(axis=1, keepdims=True)


def embedding_classifier_attack_score(
    flow_df: pd.DataFrame,
    checkpoint_path: str | Path,
    proto_encoder_path: str | Path,
    port_encoder_path: str | Path,
) -> pd.DataFrame:
    """
    Вероятность атаки по сети с embedding порт/протокол + числовой вектор (кейс 4).

    Если torch или файлы недоступны, возвращает нули.
    """
    if torch is None:
        return pd.DataFrame({"l2_emb_attack_score": 0.0}, index=flow_df.index)

    from sklearn.preprocessing import LabelEncoder

    from src.models.embeddings_model import FlowEmbeddingNet

    ckpt = _torch_load(checkpoint_path)
    le_proto: LabelEncoder = joblib.load(proto_encoder_path)
    le_port: LabelEncoder = joblib.load(port_encoder_path)

    proto_col = ckpt.get("proto_col", "Protocol")
    port_col = ckpt.get("port_col", "Destination Port")
    num_cols = list(ckpt.get("numeric_cols", []))
    if proto_col not in flow_df.columns or port_col not in flow_df.columns:
        return pd.DataFrame({"l2_emb_attack_score": 0.0}, index=flow_df.index)

    def _safe_idx(le: LabelEncoder, series: pd.Series) -> np.ndarray:
        s = series.astype(str)
        classes = set(le.classes_)
        out = np.zeros(len(s), dtype=np.int64)
        for i, v in enumerate(s):
            if v in classes:
                out[i] = int(le.transform([v])[0]) + 1
            else:
                out[i] = 0
        return out

    port_idx = _safe_idx(le_port, flow_df[port_col])
    proto_idx = _safe_idx(le_proto, flow_df[proto_col])
    use = [c for c in num_cols if c in flow_df.columns]
    if not use:
        return pd.DataFrame({"l2_emb_attack_score": 0.0}, index=flow_df.index)
    X_num = flow_df[use].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float32).values

    n_port = int(ckpt["num_ports"])
    n_proto = int(ckpt["num_protocols"])
    n_num = int(ckpt["n_numeric"])
    if X_num.shape[1] != n_num:
        pad = np.zeros((len(flow_df), n_num), dtype=np.float32)
        pad[:, : X_num.shape[1]] = X_num
        X_num = pad

    model = FlowEmbeddingNet(
        num_ports=n_port,
        num_protocols=n_proto,
        n_numeric=n_num,
        embed_dim=int(ckpt["embed_dim"]),
        hidden=int(ckpt["hidden"]),
        n_classes=2,
    )
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    with torch.no_grad():
        logits = model(
            torch.from_numpy(port_idx).long(),
            torch.from_numpy(proto_idx).long(),
            torch.from_numpy(X_num).float(),
        ).numpy()
        proba = _softmax(logits)
        attack = 1.0 - proba[:, 0]

    return pd.DataFrame({"l2_emb_attack_score": attack}, index=flow_df.index)


def raw_header_cnn_attack_score(
    flow_df: pd.DataFrame,
    checkpoint_path: str | Path,
    label_encoder_path: str | Path,
) -> pd.DataFrame:
    """
    Вероятность атаки по CNN над сырыми байтами IP-заголовков (колонки hb_*).
    """
    if torch is None:
        return pd.DataFrame({"l2_hdr_cnn_attack_score": 0.0}, index=flow_df.index)
    ckpt_path = Path(checkpoint_path)
    if not ckpt_path.is_file():
        return pd.DataFrame({"l2_hdr_cnn_attack_score": 0.0}, index=flow_df.index)

    from src.models.train_raw_header_cnn import _HeaderByteCNN

    ckpt = _torch_load(ckpt_path)
    hb_cols = list(ckpt.get("hb_columns", []))
    if not hb_cols or any(c not in flow_df.columns for c in hb_cols):
        return pd.DataFrame({"l2_hdr_cnn_attack_score": 0.0}, index=flow_df.index)

    le = joblib.load(label_encoder_path)
    classes = list(le.classes_)
    benign_idx = None
    for i, c in enumerate(classes):
        if str(c).upper() == "BENIGN":
            benign_idx = i
            break

    seq_len = int(ckpt["seq_len"])
    n_classes = int(ckpt["n_classes"])
    model = _HeaderByteCNN(seq_len, n_classes)
    model.load_state_dict(ckpt["state_dict"])
    model.eval()

    Xa = flow_df[hb_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float32).values
    Xa = np.ascontiguousarray(Xa)
    with torch.no_grad():
        logits = model(torch.from_numpy(Xa)).numpy()
        proba = _softmax(logits)
        if benign_idx is None:
            attack = proba.max(axis=1)
        else:
            attack = 1.0 - proba[:, benign_idx]
    return pd.DataFrame({"l2_hdr_cnn_attack_score": attack}, index=flow_df.index)
