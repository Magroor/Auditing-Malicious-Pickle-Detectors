"""Three-way verdict of PREREGISTRATION section 14.2.

A file the static reader did not finish (meta_baseline.cap_reason: byte_cap, op_cap or malformed)
gets UNVERIFIED and goes to a secondary review instead of being scored. Every other file gets the
detector's verdict. Static only: the verdict uses file metadata and a prediction, never the file.
"""
from __future__ import annotations

import meta_baseline as MB

SAFE, MALICIOUS, UNVERIFIED = "SAFE", "MALICIOUS", "UNVERIFIED"


def verdict(pred: int, meta: dict) -> str:
    if MB.cap_reason(meta) is not None:
        return UNVERIFIED
    return MALICIOUS if int(pred) == 1 else SAFE


def verdicts(preds, metas) -> list[str]:
    return [verdict(p, m) for p, m in zip(preds, metas)]
