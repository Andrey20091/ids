# =============================================================================
# LSTM-классификатор по скользящим окнам векторов признаков (кейс 4, L2).
# =============================================================================
"""
LSTM по **временным окнам векторов признаков потока** (кейс 4, ТЗ).

В терминах ТЗ это анализ временного контекста трафика: каждое окно — последовательность
измерений по потоку (агрегаты CICIDS + L2-признаки), упорядоченных по времени/строке CSV.
Для корректной симуляции «реального времени» сортируйте строки по ``Timestamp`` до детекции.
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


class _LSTMClassifier(nn.Module):
    def __init__(self, n_features: int, hidden_size: int, num_classes: int):
        super().__init__()
        self.lstm = nn.LSTM(n_features, hidden_size, batch_first=True)
        self.fc = nn.Linear(hidden_size, num_classes)

    def forward(self, x):
        out, _ = self.lstm(x)
        return self.fc(out[:, -1, :])


def _windows(X: np.ndarray, seq_len: int) -> np.ndarray:
    if len(X) < seq_len:
        raise ValueError("Need at least sequence_length rows")
    stacks = [X[i : i + seq_len] for i in range(0, len(X) - seq_len + 1)]
    return np.stack(stacks, axis=0).astype(np.float32)


def _windows_for_end_range(X: np.ndarray, seq_len: int, end_min: int, end_max_exclusive: int) -> tuple[np.ndarray, np.ndarray]:
    """Окна, у которых последняя строка имеет индекс в [end_min, end_max_exclusive)."""
    if end_max_exclusive <= end_min or end_min < seq_len - 1:
        return np.empty((0, seq_len, X.shape[1]), dtype=np.float32), np.empty(0, dtype=np.int64)
    ends = list(range(max(end_min, seq_len - 1), end_max_exclusive))
    if not ends:
        return np.empty((0, seq_len, X.shape[1]), dtype=np.float32), np.empty(0, dtype=np.int64)
    stacks = [X[e - seq_len + 1 : e + 1] for e in ends]
    y_idx = np.array(ends, dtype=np.int64)
    return np.stack(stacks, axis=0).astype(np.float32), y_idx


def train_lstm(
    X: pd.DataFrame,
    y: pd.Series,
    artifacts_dir: str | Path,
    sequence_length: int = 20,
    hidden_size: int = 64,
    epochs: int = 20,
    batch_size: int = 128,
    learning_rate: float = 1e-3,
    random_state: int = 42,
    val_start_row: int | None = None,
) -> dict:
    if _TORCH_ERR is not None:
        raise ImportError("Install torch: pip install torch") from _TORCH_ERR

    from sklearn.preprocessing import LabelEncoder

    artifacts_dir = Path(artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(random_state)
    np.random.seed(random_state)

    le = LabelEncoder()
    y_enc = le.fit_transform(y.astype(str))
    num_classes = len(le.classes_)

    Xa = X.astype(np.float32).values
    n = len(Xa)
    seq = sequence_length
    val_f1: float | None = None

    if val_start_row is None:
        W = _windows(Xa, seq)
        yw = y_enc[seq - 1 :]
    else:
        if val_start_row <= seq - 1 or val_start_row >= n:
            raise ValueError("val_start_row must be in [sequence_length, n)")
        W_tr, _ = _windows_for_end_range(Xa, seq, seq - 1, val_start_row)
        y_tr = y_enc[seq - 1 : val_start_row]
        if len(W_tr) == 0:
            raise ValueError("No LSTM training windows for given val_start_row")
        W = W_tr
        yw = y_tr

    ds = TensorDataset(torch.from_numpy(W), torch.from_numpy(yw.astype(np.int64)))
    loader = DataLoader(ds, batch_size=batch_size, shuffle=True)

    model = _LSTMClassifier(X.shape[1], hidden_size, num_classes)
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

    if val_start_row is not None:
        from sklearn.metrics import f1_score

        W_va, y_end = _windows_for_end_range(Xa, seq, val_start_row, n)
        if len(W_va) > 0:
            model.eval()
            with torch.no_grad():
                logits_va = model(torch.from_numpy(W_va))
                pred_va = logits_va.argmax(dim=1).numpy()
            y_true = y_enc[y_end]
            # Бинарно: не первый класс как атака, если классов больше двух
            if num_classes == 2:
                val_f1 = float(f1_score(y_true, pred_va, zero_division=0))
            else:
                val_f1 = float(f1_score(y_true, pred_va, average="macro", zero_division=0))

    path = artifacts_dir / "lstm_model.pt"
    torch.save(
        {
            "state_dict": model.state_dict(),
            "n_features": X.shape[1],
            "hidden_size": hidden_size,
            "num_classes": num_classes,
            "sequence_length": sequence_length,
            "classes": le.classes_.tolist(),
        },
        path,
    )
    import joblib

    joblib.dump(le, artifacts_dir / "lstm_label_encoder.joblib")
    out: dict = {"model_path": str(path)}
    if val_f1 is not None:
        out["val_f1"] = val_f1
    return out
