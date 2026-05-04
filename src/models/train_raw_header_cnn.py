# =============================================================================
# CNN по сырым байтам IP-заголовков (плоский вектор на поток) — ТЗ кейс 4.
# =============================================================================
"""1D CNN on flattened per-flow header byte tensor (normalized0–1)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

try:
    import torch
    import torch.nn as nn
except ImportError:
    torch = None
    nn = None


if nn is not None:

    class _HeaderByteCNN(nn.Module):
        def __init__(self, seq_len: int, n_classes: int):
            super().__init__()
            self.seq_len = seq_len
            self.net = nn.Sequential(
                nn.Conv1d(1, 32, kernel_size=9, stride=4, padding=2),
                nn.ReLU(inplace=True),
                nn.Conv1d(32, 64, kernel_size=9, stride=4, padding=2),
                nn.ReLU(inplace=True),
                nn.AdaptiveAvgPool1d(1),
            )
            self.fc = nn.Linear(64, n_classes)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            # x: (batch, seq_len) -> (batch, 1, seq_len)
            x = x.unsqueeze(1)
            h = self.net(x).squeeze(-1)
            return self.fc(h)

else:
    _HeaderByteCNN = None  # type: ignore[misc, assignment]


def train_raw_header_cnn(
    X: pd.DataFrame,
    y: pd.Series,
    artifacts_dir: str | Path,
    hb_columns: list[str],
    epochs: int = 25,
    batch_size: int = 128,
    learning_rate: float = 1e-3,
    random_state: int = 42,
) -> dict:
    if torch is None:
        raise ImportError("torch required")
    from sklearn.preprocessing import LabelEncoder

    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    use = [c for c in hb_columns if c in X.columns]
    if not use or len(use) < 8:
        raise ValueError("No header byte columns for CNN")
    Xa = X[use].apply(pd.to_numeric, errors="coerce").fillna(0.0).astype(np.float32).values
    if float(np.abs(Xa).sum()) < 1e-9:
        raise ValueError("Header byte matrix is all zeros — run scripts/16_build_header_byte_dataset.py + prepare --header-bytes-npz")

    le = LabelEncoder()
    y_enc = le.fit_transform(y.astype(str))
    n_classes = len(le.classes_)
    seq_len = Xa.shape[1]

    torch.manual_seed(random_state)
    Xa = np.ascontiguousarray(Xa)
    y_t = np.ascontiguousarray(y_enc.astype(np.int64))
    ds = torch.utils.data.TensorDataset(torch.from_numpy(Xa), torch.from_numpy(y_t))
    loader = torch.utils.data.DataLoader(ds, batch_size=batch_size, shuffle=True)
    model = _HeaderByteCNN(seq_len, n_classes)
    opt = torch.optim.Adam(model.parameters(), lr=learning_rate)
    loss_fn = nn.CrossEntropyLoss()
    model.train()
    for _ in range(epochs):
        for xb, yb in loader:
            opt.zero_grad()
            logits = model(xb)
            loss = loss_fn(logits, yb)
            loss.backward()
            opt.step()

    path = artifacts_dir / "raw_header_cnn.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "seq_len": seq_len,
            "n_classes": n_classes,
            "hb_columns": use,
        },
        path,
    )
    import joblib

    joblib.dump(le, artifacts_dir / "raw_header_cnn_label_encoder.joblib")
    return {"model_path": str(path), "n_classes": n_classes, "seq_len": seq_len}
