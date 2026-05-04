# =============================================================================
# Слои Embedding для порта и протокола + MLP (кейс 4, заголовки пакетов).
# =============================================================================
"""
Embedding-слои по полям уровня заголовка потока (протокол, порт) + числовой вектор признаков.

Соответствует ТЗ кейса 4: табличное представление «заголовков» (категории + агрегаты)
подаётся в сеть как ``concat(embed(port), embed(protocol), numeric_vec)``.
"""

from __future__ import annotations

try:
    import torch
    import torch.nn as nn
except ImportError:
    torch = None
    nn = None


if nn is not None:

    class FlowEmbeddingNet(nn.Module):
        """Small MLP with Embedding for port and protocol indices."""

        def __init__(
            self,
            num_ports: int,
            num_protocols: int,
            n_numeric: int,
            embed_dim: int = 16,
            hidden: int = 64,
            n_classes: int = 2,
        ):
            super().__init__()
            self.port_emb = nn.Embedding(num_ports + 1, embed_dim, padding_idx=0)
            self.proto_emb = nn.Embedding(num_protocols + 1, embed_dim, padding_idx=0)
            in_dim = embed_dim * 2 + n_numeric
            self.net = nn.Sequential(
                nn.Linear(in_dim, hidden),
                nn.ReLU(),
                nn.Linear(hidden, n_classes),
            )

        def forward(self, port_idx, proto_idx, numeric):
            pe = self.port_emb(port_idx)
            pr = self.proto_emb(proto_idx)
            x = torch.cat([pe, pr, numeric], dim=-1)
            return self.net(x)

else:
    FlowEmbeddingNet = None  # type: ignore[misc, assignment]
