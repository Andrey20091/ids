# =============================================================================
# Autoencoder: реконструкция нормального трафика, порог по MSE (кейс 4, L2).
# =============================================================================
"""
Autoencoder for anomaly detection (ТЗ).

Requires torch. Train on normal-only subset; threshold on reconstruction MSE.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
except ImportError as e:
    torch = None
    nn = None
    DataLoader = None
    TensorDataset = None
    _TORCH_ERR = e
else:
    _TORCH_ERR = None


class _AE(nn.Module):
    def __init__(self, n_features: int, encoding_dim: int = 32):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(n_features, max(encoding_dim * 2, 16)),
            nn.ReLU(),
            nn.Linear(max(encoding_dim * 2, 16), encoding_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(encoding_dim, max(encoding_dim * 2, 16)),
            nn.ReLU(),
            nn.Linear(max(encoding_dim * 2, 16), n_features),
        )

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z)


def train_autoencoder(
    X_normal: pd.DataFrame,
    artifacts_dir: str | Path,
    encoding_dim: int = 32,
    epochs: int = 30,
    batch_size: int = 256,
    learning_rate: float = 1e-3,
    random_state: int = 42,
    X_val_normal: pd.DataFrame | None = None,
) -> dict:
    if _TORCH_ERR is not None:
        raise ImportError("Install torch: pip install torch") from _TORCH_ERR

    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(random_state)
    np.random.seed(random_state)

    Xn = X_normal.astype(np.float32).values
    n_features = Xn.shape[1]
    ds = TensorDataset(torch.from_numpy(Xn))
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True)

    model = _AE(n_features, encoding_dim=encoding_dim)
    opt = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.MSELoss()

    model.train()
    for _ in range(epochs):
        for (batch,) in loader:
            opt.zero_grad()
            recon = model(batch)
            loss = loss_fn(recon, batch)
            loss.backward()
            opt.step()

    model.eval()
    with torch.no_grad():
        recon = model(torch.from_numpy(Xn))
        mse = ((recon.numpy() - Xn) ** 2).mean(axis=1)
    threshold = float(np.percentile(mse, 95))

    val_mse_mean: float | None = None
    if X_val_normal is not None and len(X_val_normal) > 0:
        if X_val_normal.shape[1] != n_features:
            raise ValueError("X_val_normal must have same columns count as X_normal")
        Xv = X_val_normal.astype(np.float32).values
        with torch.no_grad():
            recon_v = model(torch.from_numpy(Xv))
            val_mse_mean = float(((recon_v.numpy() - Xv) ** 2).mean())

    path = artifacts_dir / "ae_model.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "n_features": n_features,
            "encoding_dim": encoding_dim,
            "threshold": threshold,
        },
        path,
    )
    out: dict = {"model_path": str(path), "threshold": threshold}
    if val_mse_mean is not None:
        out["val_mse_mean"] = val_mse_mean
    return out
