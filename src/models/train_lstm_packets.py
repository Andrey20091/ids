# =============================================================================
# LSTM по последовательности пакетов внутри потока (опциональный режим кейса 4).
# =============================================================================
"""Обучение на NPZ из scripts/20_build_packet_lstm_dataset.py."""

from __future__ import annotations

from pathlib import Path

import numpy as np

try:
    import torch
    import torch.nn as nn
except ImportError:
    torch = None  # type: ignore[misc, assignment]
    nn = None  # type: ignore[misc, assignment]


class _PacketLSTM(nn.Module):
    def __init__(self, feat_dim: int, hidden: int, num_classes: int):
        super().__init__()
        self.lstm = nn.LSTM(feat_dim, hidden, batch_first=True, num_layers=1)
        self.fc = nn.Linear(hidden, num_classes)

    def forward(self, x: "torch.Tensor") -> "torch.Tensor":
        h, _ = self.lstm(x)
        return self.fc(h[:, -1, :])


def train_lstm_packets(
    X: np.ndarray,
    y: np.ndarray,
    mask: np.ndarray,
    artifacts_dir: str | Path,
    *,
    hidden_size: int = 64,
    epochs: int = 15,
    batch_size: int = 64,
    learning_rate: float = 1e-3,
) -> dict:
    """
    X: (N, K, F), y: (N,) binary, mask: (N,) train only where mask True.
    """
    if torch is None:
        raise ImportError("torch required")
    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    use = mask.astype(bool) & (y >= 0)
    if not use.any():
        raise ValueError("no rows with packet features (mask all False)")

    Xa = torch.from_numpy(X[use].astype(np.float32))
    ya = torch.from_numpy(y[use].astype(np.int64))
    if ya.max() == ya.min():
        raise ValueError("packet LSTM needs both classes in y (BENIGN and attack rows)")
    n = Xa.shape[0]
    k, f = int(Xa.shape[1]), int(Xa.shape[2])
    num_classes = 2
    model = _PacketLSTM(f, hidden_size, num_classes)
    opt = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.CrossEntropyLoss()
    model.train()
    for _ in range(epochs):
        perm = torch.randperm(n)
        for i in range(0, n, batch_size):
            idx = perm[i : i + batch_size]
            xb, yb = Xa[idx], ya[idx]
            opt.zero_grad()
            logits = model(xb)
            loss = loss_fn(logits, yb)
            loss.backward()
            opt.step()

    path = artifacts_dir / "lstm_packets_model.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "k_packets": k,
            "feat_dim": f,
            "hidden_size": hidden_size,
            "num_classes": num_classes,
        },
        path,
    )
    return {"model_path": str(path)}


def infer_lstm_packets(X: np.ndarray, model_path: str | Path) -> np.ndarray:
    """Вернуть P(attack) по последнему таймстепу, shape (N,)."""
    if torch is None:
        return np.zeros(X.shape[0], dtype=np.float32)
    model_path = Path(model_path)
    blob = torch.load(model_path, map_location="cpu", weights_only=False)
    f = int(blob["feat_dim"])
    h = int(blob["hidden_size"])
    nc = int(blob["num_classes"])
    model = _PacketLSTM(f, h, nc)
    model.load_state_dict(blob["state_dict"])
    model.eval()
    with torch.no_grad():
        t = torch.from_numpy(X.astype(np.float32))
        logits = model(t)
        proba = torch.softmax(logits, dim=1)[:, 1].numpy()
    return proba.astype(np.float32)
