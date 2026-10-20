"""Robustness-v2 detector: a 1D CNN over the SEMANTIC canonical opcode stream,
fused with a SafePickle-style frequency branch and two LEARNED, monotone danger
gates.

Design and why it keeps both robustness and specificity
--------------------------------------------------------
Two parts make up the score, `final = disc(seq, freq) + evidence(tok, mod, dead)`:

1. Discriminative branch `disc`: a CNN over the semantic canonical opcode stream
   plus a frequency histogram taken over that same stream (the SafePickle
   representation, but padding-invariant). Both inputs are *invariant* to any
   dead-code insertion, because the semantic canonicaliser drops dead code, so
   `disc` does not move under padding. This branch carries clean benign/malicious
   separation, so its specificity is SafePickle-like.

2. Evidence `evidence >= 0`: two gates plus a dead-code term.
     - token gate: for each high-precision raw-byte token present as its own
       identifier (not as a substring of a longer name), a LEARNED danger
       >= 0, then MAX over tokens;
     - import gate: for each live non-allowlisted import module, a LEARNED danger
       >= 0, then MAX over modules;
     - dead term: a non-negative weight times log1p(dead-node count).
   A `max` over a set and a non-negative dead term can only rise when content is
   inserted, and each danger is >= 0, so `evidence` is monotone non-decreasing
   under insertion. Because `disc` is invariant and `evidence` only rises,
   `final` is monotone non-decreasing under insertion -> a flagged file stays
   flagged under any padding (the robustness guarantee).

   The token list is a PRECISION subset of the v1 denylist. Tokens that are
   near-universal atoms in legitimate checkpoints (getattr, builtins) are
   excluded: a monotone Softplus gate cannot unlearn them, so they only inflate
   benign scores. Remaining tokens are matched at identifier boundaries, so
   ``pty`` does not fire on ``empty``, ``eval`` does not fire on ``evaluate``,
   ``exec`` does not fire on ``execute``, and ``system`` does not fire on
   ``filesystem``. Module atoms that survive truncation (importlib, operator)
   and ``partial`` stay, because those are the only bytes left on some broken
   gadget streams. Truly dangerous items (os.system, subprocess, eval-as-atom)
   still raise the score and still catch nullifAI broken streams.

Training uses DEEP SUPERVISION: the loss adds an auxiliary term on `disc` alone
and on `evidence` alone, so each part is forced to be discriminative on its own
rather than letting one branch explain all the loss and leave the gates untrained.

Everything is static. No file is ever loaded; the gates read opcodes and raw bytes.
"""

from __future__ import annotations

import zlib
from typing import List, Tuple

import numpy as np

from .features import OPCODE_INDEX, unwrap
from .semantic import semantic_canonicalize

MAXLEN = 256                     # semantic ops fed to the conv branch
VOCAB = len(OPCODE_INDEX) + 1    # 0 is the padding index
FREQ_DIM = len(OPCODE_INDEX)     # opcode-frequency histogram (SafePickle view)
V_MOD = 4096                     # hashed module-name buckets
K_MOD = 16                       # max non-allowlisted modules scored per file
AUX_WEIGHT = 0.3                 # deep-supervision weight on disc and evidence

# High-precision tokens for the monotone evidence head. This is NOT the v1
# DANGEROUS_TOKENS list: that list is matched as a raw substring and includes
# atoms that sit in almost every real checkpoint (getattr, builtins) plus
# tokens that are substrings of benign words (pty subset of empty, eval of
# evaluate). Softplus gates cannot drive those to zero, so they leaked 26 of
# the 32 head-to-head false positives. v1 feature extraction is unchanged.
EVIDENCE_TOKENS = [
    b"subprocess", b"Popen", b"popen", b"eval", b"exec",
    b"posix", b"commands", b"runpy", b"pty", b"socket", b"__reduce__",
    b"__import__", b"importlib", b"import_module", b"operator", b"partial",
    b"check_output", b"pydoc", b"pipepager", b"methodcaller",
    b"b64decode", b"marshal", b"ctypes", b"/bin/sh",
    b"/bin/bash", b"bash -i", b"dup2", b"AF_INET", b"SOCK_STREAM",
    b"execve", b"setsid", b"cmd.exe", b"powershell", b"urlretrieve",
    b"urlopen", b"/dev/tcp", b"webbrowser",
    b"system",
]
N_TOK = len(EVIDENCE_TOKENS) + 1    # token ids (+1 for padding)
K_TOK = len(EVIDENCE_TOKENS)        # max tokens scored per file

# Identifier bytes: a token is present only when it is not glued to a longer
# name (``empty`` must not match ``pty``). Path/shell tokens start with a
# non-identifier and keep ordinary substring search.
_IDENT = set(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")


def token_in_bytes(data: bytes, tok: bytes) -> bool:
    """True iff ``tok`` occurs as its own identifier or path atom in ``data``.

    Protocol-0 GLOBAL/INST write ``cposix\\n`` / ``iposix\\n``, so the opcode
    byte is glued to the module name. Treat that opcode+newline frame as a
    boundary; do not treat a lone ``c`` inside an ordinary word as one
    (``account`` must not match ``count``).
    """
    if not tok or not data:
        return False
    if tok[0] not in _IDENT:
        return tok in data
    if b"c" + tok + b"\n" in data or b"i" + tok + b"\n" in data:
        return True
    start = 0
    n = len(tok)
    while True:
        i = data.find(tok, start)
        if i < 0:
            return False
        left_ok = i == 0 or data[i - 1] not in _IDENT
        j = i + n
        right_ok = j >= len(data) or data[j] not in _IDENT
        if left_ok and right_ok:
            return True
        start = i + 1


def _module_bucket(module: str) -> int:
    """Stable hash of a top-level module name to 1..V_MOD (0 = padding)."""
    top = module.split(".", 1)[0]
    return zlib.crc32(top.encode("utf-8", "replace")) % V_MOD + 1


def encode(data: bytes) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Return (seq, freq, token ids, module buckets, dead) for one file.

    seq and freq come from the semantic canonical stream (padding-invariant).
    token ids index EVIDENCE_TOKENS present as identifier atoms in the raw
    bytes (so a broken stream is still represented, without matching ``pty``
    inside ``empty``). module buckets hash the live non-allowlisted import
    modules. dead = log1p(dead-node count) + 1 if the stream is broken.
    """
    inner = unwrap(data)
    ops, stats = semantic_canonicalize(inner, view="effects")

    seq = [OPCODE_INDEX[name] + 1 for name, _a, _p in ops if name in OPCODE_INDEX][:MAXLEN]
    seq = seq + [0] * (MAXLEN - len(seq))

    hist = np.zeros(FREQ_DIM, dtype=np.float32)
    for name, _a, _p in ops:
        j = OPCODE_INDEX.get(name)
        if j is not None:
            hist[j] += 1.0
    total = float(hist.sum())
    if total > 0:
        hist /= total

    toks = [i + 1 for i, tok in enumerate(EVIDENCE_TOKENS)
            if token_in_bytes(inner, tok)][:K_TOK]
    toks = toks + [0] * (K_TOK - len(toks))

    mods = sorted({_module_bucket(item.split(" ", 1)[0])
                   for item in stats.get("nonallow_imports", [])})[:K_MOD]
    mods = mods + [0] * (K_MOD - len(mods))

    # Broken / unverified streams (truncation, 7z prefix, opcode cap) have an
    # empty canonical sequence, so disc looks benign. Adding the broken flag
    # here is monotone: a well-formed file can only become broken, never the
    # reverse, under insertion.
    dead = np.array([np.log1p(stats.get("n_dead_nodes", 0))
                     + float(bool(stats.get("broken", False)))], dtype=np.float32)
    return (np.array(seq, dtype=np.int64), hist,
            np.array(toks, dtype=np.int64), np.array(mods, dtype=np.int64), dead)


def encode_batch(blobs: List[bytes]):
    if not blobs:
        return (np.zeros((0, MAXLEN), np.int64), np.zeros((0, FREQ_DIM), np.float32),
                np.zeros((0, K_TOK), np.int64), np.zeros((0, K_MOD), np.int64),
                np.zeros((0, 1), np.float32))
    s, f, t, m, d = zip(*(encode(b) for b in blobs))
    return np.stack(s), np.stack(f), np.stack(t), np.stack(m), np.stack(d)


def _build_model():
    import torch
    import torch.nn as nn

    class _Gate(nn.Module):
        """max over present items of a learned, non-negative per-item danger.
        Returns 0 when no item is present. Monotone: adding an item (or raising a
        padding-mask slot) cannot lower the max."""

        def __init__(self, vocab: int, emb: int):
            super().__init__()
            self.emb = nn.Embedding(vocab, emb, padding_idx=0)
            self.lin1 = nn.Linear(emb, emb)
            self.lin2 = nn.Linear(emb, 1)
            self.act = nn.ReLU()
            self.soft = nn.Softplus()

        def forward(self, ids):                        # ids: (B, K)
            mask = (ids != 0).float()
            danger = self.soft(self.lin2(self.act(self.lin1(self.emb(ids))))).squeeze(-1)
            danger = danger * mask                     # padding contributes 0
            return danger.max(dim=1).values            # (B,) >= 0

    class OpcodeCNNv2(nn.Module):
        def __init__(self, vocab=VOCAB, emb=32, ch=64, freq_dim=FREQ_DIM):
            super().__init__()
            self.emb = nn.Embedding(vocab, emb, padding_idx=0)
            self.conv1 = nn.Conv1d(emb, ch, kernel_size=5, padding=2)
            self.conv2 = nn.Conv1d(emb, ch, kernel_size=3, padding=1)
            self.pool = nn.AdaptiveMaxPool1d(1)
            self.freq = nn.Sequential(nn.Linear(freq_dim, 32), nn.ReLU())
            self.fc1 = nn.Linear(ch * 2 + 32, 32)
            self.drop = nn.Dropout(0.2)
            self.fc2 = nn.Linear(32, 1)
            self.act = nn.ReLU()
            self.tok_gate = _Gate(N_TOK, 8)
            self.mod_gate = _Gate(V_MOD + 1, 16)
            self.raw_wdead = nn.Parameter(torch.zeros(1))   # softplus -> >= 0
            self.evid_bias = nn.Parameter(torch.zeros(1))   # used only in the aux loss

        def disc_logit(self, seq, freq):
            x = self.emb(seq).transpose(1, 2)
            a = self.pool(self.act(self.conv1(x))).squeeze(-1)
            b = self.pool(self.act(self.conv2(x))).squeeze(-1)
            h = self.act(self.fc1(self.drop(torch.cat([a, b, self.freq(freq)], dim=1))))
            return self.fc2(h).squeeze(-1)

        def evidence(self, tok, mod, dead):
            wdead = torch.nn.functional.softplus(self.raw_wdead)
            return self.tok_gate(tok) + self.mod_gate(mod) + dead.squeeze(-1) * wdead

        def forward(self, seq, freq, tok, mod, dead):
            # disc is invariant to dead-code insertion (semantic input); evidence
            # is monotone non-decreasing under insertion. So the total cannot drop.
            return self.disc_logit(seq, freq) + self.evidence(tok, mod, dead)

    return OpcodeCNNv2()


class DeepDetectorV2:
    def __init__(self, model=None):
        self.model = model

    def predict_proba(self, blob: bytes) -> float:
        import torch
        s, f, t, m, d = encode_batch([blob])
        self.model.eval()
        with torch.no_grad():
            logit = self.model(torch.tensor(s), torch.tensor(f), torch.tensor(t),
                               torch.tensor(m), torch.tensor(d))
            return float(torch.sigmoid(logit)[0])

    def predict(self, blob: bytes) -> int:
        return int(self.predict_proba(blob) >= 0.5)

    def save(self, path: str) -> None:
        import torch
        torch.save(self.model.state_dict(), path)

    @classmethod
    def load(cls, path: str) -> "DeepDetectorV2":
        import torch
        model = _build_model()
        model.load_state_dict(torch.load(path, map_location="cpu", weights_only=True))
        model.eval()
        return cls(model)


def train_cnn_v2_enc(seqs, freqs, toks, mods, deads, labels, epochs: int = 40,
                     seed: int = 0, aux: float = AUX_WEIGHT) -> "DeepDetectorV2":
    """Train on pre-encoded arrays with deep supervision: the loss adds an
    auxiliary BCE on the discriminative branch alone and on the evidence alone,
    so the frequency/sequence branch learns clean separation and the gates learn
    per-item danger instead of staying at their initial values."""
    import torch
    torch.manual_seed(seed)
    Xs = torch.tensor(seqs); Xf = torch.tensor(freqs); Xt = torch.tensor(toks)
    Xm = torch.tensor(mods); Xd = torch.tensor(deads)
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
            disc = model.disc_logit(Xs[idx], Xf[idx])
            evid = model.evidence(Xt[idx], Xm[idx], Xd[idx])
            yb = y[idx]
            loss = (loss_fn(disc + evid, yb)
                    + aux * loss_fn(disc, yb)
                    + aux * loss_fn(evid + model.evid_bias, yb))
            loss.backward()
            opt.step()
    return DeepDetectorV2(model)


def cnn_v2_proba(det: "DeepDetectorV2", seqs, freqs, toks, mods, deads) -> np.ndarray:
    import torch
    det.model.eval()
    with torch.no_grad():
        logits = det.model(torch.tensor(seqs), torch.tensor(freqs), torch.tensor(toks),
                           torch.tensor(mods), torch.tensor(deads))
        return torch.sigmoid(logits).numpy()


def cnn_v2_components(det: "DeepDetectorV2", seqs, freqs, toks, mods, deads) -> dict:
    """Per-file breakdown of the logit: the discriminative branch and each evidence
    term separately. `final = disc + tok + mod + dead`. Used to see which signal
    drives a decision (for example which one is responsible for a false positive)."""
    import torch
    det.model.eval()
    with torch.no_grad():
        s = torch.tensor(seqs); f = torch.tensor(freqs)
        t = torch.tensor(toks); m = torch.tensor(mods); d = torch.tensor(deads)
        wdead = torch.nn.functional.softplus(det.model.raw_wdead)
        return {"disc": det.model.disc_logit(s, f).numpy(),
                "tok": det.model.tok_gate(t).numpy(),
                "mod": det.model.mod_gate(m).numpy(),
                "dead": (d.squeeze(-1) * wdead).numpy()}


def train_cnn_v2(blobs: List[bytes], labels: np.ndarray, epochs: int = 40,
                 seed: int = 0) -> DeepDetectorV2:
    s, f, t, m, d = encode_batch(blobs)
    return train_cnn_v2_enc(s, f, t, m, d, labels, epochs=epochs, seed=seed)
