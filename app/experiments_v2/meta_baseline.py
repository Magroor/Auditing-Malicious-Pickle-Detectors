"""Shared helpers for the two baselines every results table must carry (PREREGISTRATION
amendment 2026-10-04): the metadata-only baseline META, and the fail-closed policy.

META is a logistic regression on file metadata (container, protocol, sizes, member and stream
counts, bytes after STOP). It reads no opcode *content*, but note that container, protocol and
n_streams come from whether and how the stream parses, so it is "metadata including parse
status", not "file size alone". `meta_vec` must stay identical to colab_v2_eval.meta_vec, which
produced the dev-set META numbers (a test checks this).

Fail-closed: a stream the static reader could not fully read (a byte or opcode cap was hit, or the
stream is malformed) is unverified, and a scanner that is fail-closed flags it whatever the model
says. `unverified` and `cap_reason` read only the per-file meta dict written by
colab_v2_eval.encode_file. Static only; nothing here touches sample bytes.
"""
from __future__ import annotations

import numpy as np

import picklescan_ml.features as F


def meta_vec(m):
    """Container, protocol, sizes and member counts (identical to colab_v2_eval.meta_vec)."""
    v = [float(m["container"] == c) for c in ("zip", "pickle", "other")]
    v += [float(m.get("proto") == p) for p in (0, 2, 3, 4, 5)]
    v += [np.log1p(m["file_bytes"]), np.log1p(m.get("inner_bytes", m["file_bytes"])),
          float(m.get("n_pkl_members") or 0), float(m.get("n_streams") or 0),
          float(m.get("trailing_after_stop") or 0)]
    return v


def fit_meta(metas, y, seed=0):
    """Fit META on a list of meta dicts; return metas -> P(malicious). Threshold 0.5 as pre-registered."""
    from sklearn.linear_model import LogisticRegression
    lr = LogisticRegression(max_iter=5000, random_state=int(seed))
    lr.fit(np.array([meta_vec(m) for m in metas], dtype=float), np.asarray(y))
    return lambda ms: lr.predict_proba(np.array([meta_vec(m) for m in ms], dtype=float))[:, 1]


def cap_reason(m):
    """Why the static reader did not finish this file, or None if it did.
    byte_cap: inner stream longer than MAX_STREAM_BYTES (the v1/semantic readers then read NOTHING).
    op_cap:   MAX_OPS opcodes reached. malformed: any other parse failure (incl. empty stream)."""
    if int(m.get("inner_bytes", 0) or 0) > F.MAX_STREAM_BYTES:
        return "byte_cap"
    if int(m.get("n_ops_raw", 0) or 0) >= F.MAX_OPS:
        return "op_cap"
    if int(m.get("parse_error", 0) or 0) or float(m.get("sem_broken", 0) or 0):
        return "malformed"
    return None


def unverified(m) -> bool:
    return cap_reason(m) is not None


def fail_closed(pred, metas):
    """Apply the fail-closed policy: flag every unverified file, keep the model verdict otherwise."""
    pred = np.asarray(pred).astype(int)
    return np.maximum(pred, np.array([int(unverified(m)) for m in metas]))
