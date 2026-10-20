"""A deep-learning detector: a 1D convolutional network over the opcode sequence.

The classical models in train.py use tabular features. This module adds a
genuine deep-learning model that learns directly from the ordered sequence of
pickle opcodes, combined with the byte-token and allowlist signals. It is used
to show that deep learning, like classical machine learning, beats the denylist.

Everything is static and safe. No file is ever loaded.
"""

from __future__ import annotations

import os
from typing import List, Tuple

import numpy as np

from .features import (FEATURE_NAMES, OPCODE_INDEX, extract_ops, featurize,
                       unwrap)

MAXLEN = 256
VOCAB = len(OPCODE_INDEX) + 1  # 0 is the padding index
SCALAR_KEYS = [
    "n_byte_tokens", "has_byte_token", "n_nonallowlisted_globals",
    "has_nonallowlisted_global", "picklescan_dangerous", "parse_error",
    "n_ops", "stream_len",
]
_SCALAR_IDX = [FEATURE_NAMES.index(k) for k in SCALAR_KEYS]


def opcode_sequence(data: bytes, maxlen: int = MAXLEN) -> np.ndarray:
    data = unwrap(data)
    ops, _ = extract_ops(data)
    seq = [OPCODE_INDEX[name] + 1 for name, _a, _p in ops if name in OPCODE_INDEX]
    seq = seq[:maxlen]
    if len(seq) < maxlen:
        seq = seq + [0] * (maxlen - len(seq))
    return np.array(seq, dtype=np.int64)


def scalar_features(data: bytes) -> np.ndarray:
    vec, _info = featurize(data)
    s = vec[_SCALAR_IDX].astype(np.float32).copy()
    # squash the two large-magnitude counts so they sit on a similar scale
    s[SCALAR_KEYS.index("n_ops")] = np.log1p(s[SCALAR_KEYS.index("n_ops")])
    s[SCALAR_KEYS.index("stream_len")] = np.log1p(s[SCALAR_KEYS.index("stream_len")])
    return s


def encode_batch(blobs: List[bytes]) -> Tuple[np.ndarray, np.ndarray]:
    seqs = np.stack([opcode_sequence(b) for b in blobs]) if blobs else np.zeros((0, MAXLEN), np.int64)
    scs = np.stack([scalar_features(b) for b in blobs]) if blobs else np.zeros((0, len(SCALAR_KEYS)), np.float32)
    return seqs, scs


def _build_model():
    import torch
    import torch.nn as nn

    class OpcodeCNN(nn.Module):
        def __init__(self, vocab=VOCAB, emb=32, ch=64, scalars=len(SCALAR_KEYS)):
            super().__init__()
            self.emb = nn.Embedding(vocab, emb, padding_idx=0)
            self.conv1 = nn.Conv1d(emb, ch, kernel_size=5, padding=2)
            self.conv2 = nn.Conv1d(emb, ch, kernel_size=3, padding=1)
            self.pool = nn.AdaptiveMaxPool1d(1)
            self.fc1 = nn.Linear(ch * 2 + scalars, 32)
            self.drop = nn.Dropout(0.2)
            self.fc2 = nn.Linear(32, 1)
            self.act = nn.ReLU()

        def forward(self, seq, sc):
            x = self.emb(seq).transpose(1, 2)          # (B, emb, L)
            a = self.pool(self.act(self.conv1(x))).squeeze(-1)
            b = self.pool(self.act(self.conv2(x))).squeeze(-1)
            combined = torch.cat([a, b, sc], dim=1)
            h = self.act(self.fc1(self.drop(combined)))
            return self.fc2(h).squeeze(-1)

    return OpcodeCNN()


class DeepDetector:
    def __init__(self, model=None):
        self.model = model

    def predict_proba(self, blob: bytes) -> float:
        import torch
        seq, sc = encode_batch([blob])
        self.model.eval()
        with torch.no_grad():
            logit = self.model(torch.tensor(seq), torch.tensor(sc))
            return float(torch.sigmoid(logit)[0])

    def predict(self, blob: bytes) -> int:
        return int(self.predict_proba(blob) >= 0.5)

    def save(self, path: str) -> None:
        """Save the trained weights so the CNN can be shipped and reloaded."""
        import torch
        torch.save(self.model.state_dict(), path)

    @classmethod
    def load(cls, path: str) -> "DeepDetector":
        """Load a trained CNN onto the CPU. Needs torch, which is optional."""
        import torch
        model = _build_model()
        # weights_only=True refuses to execute pickle opcodes while loading, which
        # is the safe practice a pickle-security tool should follow for its own model.
        model.load_state_dict(torch.load(path, map_location="cpu", weights_only=True))
        model.eval()
        return cls(model)


def train_cnn(blobs: List[bytes], labels: np.ndarray, epochs: int = 40, seed: int = 0) -> DeepDetector:
    import torch
    torch.manual_seed(seed)
    seqs, scs = encode_batch(blobs)
    X_seq = torch.tensor(seqs)
    X_sc = torch.tensor(scs)
    y = torch.tensor(labels.astype(np.float32))

    model = _build_model()
    pos = float(labels.sum())
    neg = float(len(labels) - pos)
    pos_weight = torch.tensor([neg / max(pos, 1.0)])
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)

    n = len(labels)
    bs = 32
    for _ep in range(epochs):
        model.train()
        perm = torch.randperm(n)
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            opt.zero_grad()
            out = model(X_seq[idx], X_sc[idx])
            loss = loss_fn(out, y[idx])
            loss.backward()
            opt.step()
    return DeepDetector(model)
