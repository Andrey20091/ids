# =============================================================================
# Обучение классификатора с Embedding по порту и протоколу (кейс 4, заголовки).
# =============================================================================
"""Обучение FlowEmbeddingNet для бинарной классификации (BENIGN vs атака)."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

try:
    import torch
    import torch.nn as nn
except ImportError:
    torch = None
    nn = None

from src.models.embeddings_model import FlowEmbeddingNet


def _safe_cat_idx(le, series: pd.Series) -> np.ndarray:
    """Индексы 1..K для известных классов, 0 — неизвестные (padding)."""
    classes = set(le.classes_)
    out: list[int] = []
    for v in series.astype(str):
        if v in classes:
            out.append(int(le.transform([v])[0]) + 1)
        else:
            out.append(0)
    return np.asarray(out, dtype=np.int64)


def train_embedding_classifier(
    df: pd.DataFrame,
    proto_col: str,
    port_col: str,
    numeric_cols: list[str],
    y_binary: pd.Series,
    artifacts_dir: str | Path,
    epochs: int = 15,
    batch_size: int = 256,
    learning_rate: float = 1e-3,
    embed_dim: int = 16,
    hidden: int = 64,
    random_state: int = 42,
    train_mask: pd.Series | None = None,
) -> dict:
    """
    Обучить небольшую сеть с embedding для Protocol и Destination Port + числовой вектор.

    Параметры
    ----------
    df : pd.DataFrame
        Потоки с категориальными и числовыми колонками.
    proto_col, port_col : str
        Имена колонок протокола и порта.
    numeric_cols : list[str]
        Числовые признаки (должны существовать в df).
    y_binary : pd.Series
        0/1 — атака или нет.
    artifacts_dir : str | Path
        Каталог для ``embedding_classifier.pt`` и энкодеров.

    Возвращает
    -----------
    dict
        loss/accuracy на последней эпохе и путь к чекпоинту.
    """
    if torch is None:
        raise ImportError("torch required for embedding classifier")
    torch.manual_seed(int(random_state))
    np.random.seed(int(random_state))

    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    use = [c for c in numeric_cols if c in df.columns]
    if not use:
        raise ValueError("No numeric columns for embedding classifier")
    if proto_col not in df.columns or port_col not in df.columns:
        raise ValueError("Protocol or port column missing")

    from sklearn.preprocessing import LabelEncoder

    le_proto = LabelEncoder()
    le_port = LabelEncoder()
    if train_mask is not None:
        tr = df.loc[train_mask].copy()
        if len(tr) < 10:
            raise ValueError("train_mask leaves too few rows for embedding classifier")
        le_proto.fit(tr[proto_col].astype(str))
        le_port.fit(tr[port_col].astype(str))
        p_idx = _safe_cat_idx(le_port, df[port_col])
        t_idx = _safe_cat_idx(le_proto, df[proto_col])
    else:
        p_idx = np.asarray(le_port.fit_transform(df[port_col].astype(str)) + 1, dtype=np.int64).copy()
        t_idx = np.asarray(le_proto.fit_transform(df[proto_col].astype(str)) + 1, dtype=np.int64).copy()
    X_num = df[use].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float32).values
    y = y_binary.astype(np.int64).to_numpy(copy=True)

    n_proto = len(le_proto.classes_)
    n_port = len(le_port.classes_)
    n_num = X_num.shape[1]

    model = FlowEmbeddingNet(
        num_ports=n_port,
        num_protocols=n_proto,
        n_numeric=n_num,
        embed_dim=embed_dim,
        hidden=hidden,
        n_classes=2,
    )
    opt = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.CrossEntropyLoss()

    # TensorDataset: (port_idx, proto_idx, numeric, y) — как FlowEmbeddingNet.forward(port, proto, x)
    if train_mask is not None:
        tm = train_mask.to_numpy() if isinstance(train_mask, pd.Series) else train_mask
        p_idx_tr = p_idx[tm]
        t_idx_tr = t_idx[tm]
        X_tr = X_num[tm]
        y_tr = y[tm]
    else:
        p_idx_tr, t_idx_tr, X_tr, y_tr = p_idx, t_idx, X_num, y
    ds = torch.utils.data.TensorDataset(
        torch.from_numpy(p_idx_tr).long(),
        torch.from_numpy(t_idx_tr).long(),
        torch.from_numpy(X_tr).float(),
        torch.from_numpy(y_tr).long(),
    )
    loader = torch.utils.data.DataLoader(ds, batch_size=batch_size, shuffle=True)

    model.train()
    last_loss = 0.0
    for _ in range(epochs):
        total = 0.0
        for batch in loader:
            port_b, proto_b, x_b, y_b = batch
            opt.zero_grad()
            logits = model(port_b, proto_b, x_b)
            loss = loss_fn(logits, y_b)
            loss.backward()
            opt.step()
            total += float(loss.item())
        last_loss = total / max(len(loader), 1)

    ckpt_path = artifacts_dir / "embedding_classifier.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "num_ports": n_port,
            "num_protocols": n_proto,
            "n_numeric": n_num,
            "embed_dim": embed_dim,
            "hidden": hidden,
            "numeric_cols": use,
            "proto_col": proto_col,
            "port_col": port_col,
        },
        ckpt_path,
    )
    joblib.dump(le_proto, artifacts_dir / "embedding_proto_encoder.joblib")
    joblib.dump(le_port, artifacts_dir / "embedding_port_encoder.joblib")

    with torch.no_grad():
        model.eval()
        logits = model(
            torch.from_numpy(p_idx).long(),
            torch.from_numpy(t_idx).long(),
            torch.from_numpy(X_num).float(),
        )
        pred = logits.argmax(dim=1).numpy()
        acc = float((pred == y).mean())

    val_acc: float | None = None
    if train_mask is not None:
        vm = ~train_mask.to_numpy() if isinstance(train_mask, pd.Series) else ~train_mask
        if vm.any():
            with torch.no_grad():
                logits_v = model(
                    torch.from_numpy(p_idx[vm]).long(),
                    torch.from_numpy(t_idx[vm]).long(),
                    torch.from_numpy(X_num[vm]).float(),
                )
                pred_v = logits_v.argmax(dim=1).numpy()
            val_acc = float((pred_v == y[vm]).mean())

    out = {"path": str(ckpt_path), "last_epoch_loss": last_loss, "train_acc": acc}
    if val_acc is not None:
        out["val_acc"] = val_acc
    out["oov_port_fraction"] = float((p_idx == 0).mean()) if len(p_idx) else 0.0
    out["oov_proto_fraction"] = float((t_idx == 0).mean()) if len(t_idx) else 0.0
    return out
