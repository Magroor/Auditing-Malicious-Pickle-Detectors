"""Train on real (SafePickle) + synthetic, evaluate with leakage-free 5-fold CV
on the real corpus. Colab only. Static and safe: files are read as bytes and only
their opcodes are analysed, never deserialised or executed.

Memory-safe: each file is featurised and encoded one at a time and only the small
feature vector (96 floats) and CNN encoding are kept, so the multi-gigabyte real
model weights are never all held in RAM at once.
"""
from __future__ import annotations

import glob
import json
import logging
import os
import sys
import time

logging.disable(logging.CRITICAL)
import numpy as np

if os.path.isdir("/content"):                    # Colab layout; elsewhere stay in the current directory
    sys.path.insert(0, "/content")
    os.chdir("/content")

from sklearn.ensemble import (ExtraTreesClassifier, GradientBoostingClassifier,  # noqa: E402
                              RandomForestClassifier)
from sklearn.metrics import f1_score, precision_score, recall_score          # noqa: E402
from sklearn.model_selection import StratifiedKFold                          # noqa: E402
try:  # training-only import; the verdict-only reproduction does not need it
    from xgboost import XGBClassifier                                            # noqa: E402
except ImportError:
    XGBClassifier = None

try:  # training-only import; the verdict-only reproduction does not need it
    from picklescan_ml.deep import (DeepDetector, _build_model,                  # noqa: E402
                                    opcode_sequence, scalar_features)
except ImportError:
    DeepDetector = None
    _build_model = None
    opcode_sequence = None
    scalar_features = None
from picklescan_ml.features import FEATURE_NAMES, featurize                  # noqa: E402
try:  # training-only import; the verdict-only reproduction does not need it
    from train_deep import augmented_training                                    # noqa: E402
except ImportError:
    augmented_training = None

DATA = "/content/safepickle"
RESULTS = "/content/results/safepickle_cv_results.json"
MAX_FILE = 80 * 1024 * 1024   # skip files larger than this (out of scope, avoids OOM)


def _encode_one(data):
    return featurize(data)[0], opcode_sequence(data), scalar_features(data)


def stream_real():
    paths = []
    for f in glob.glob(os.path.join(DATA, "**", "benign", "*"), recursive=True):
        if os.path.isfile(f):
            paths.append((f, 0))
    for f in glob.glob(os.path.join(DATA, "**", "malicious", "*"), recursive=True):
        if os.path.isfile(f):
            paths.append((f, 1))
    X, S, C, Y = [], [], [], []
    skipped = 0
    for i, (path, lab) in enumerate(paths):
        try:
            if os.path.getsize(path) > MAX_FILE:
                skipped += 1
                continue
            with open(path, "rb") as fh:
                data = fh.read()              # one file at a time, then discarded
            v, seq, sc = _encode_one(data)
        except Exception:
            skipped += 1
            continue
        X.append(v)
        S.append(seq)
        C.append(sc)
        Y.append(lab)
        del data
        if i % 100 == 0:
            print(f"  real {i}/{len(paths)}", flush=True)
    print(f"  real usable {len(Y)} (skipped {skipped})", flush=True)
    return np.vstack(X), np.stack(S), np.stack(C), np.array(Y)


def stream_synth():
    sb, sy = augmented_training()
    X, S, C = [], [], []
    for data in sb:
        v, seq, sc = _encode_one(data)
        X.append(v)
        S.append(seq)
        C.append(sc)
    return np.vstack(X), np.stack(S), np.stack(C), np.asarray(sy)


def _fit_ensemble(X, y):
    pos = float((y == 1).sum())
    neg = float((y == 0).sum())
    rf = RandomForestClassifier(n_estimators=400, class_weight="balanced_subsample",
                                random_state=0, n_jobs=-1).fit(X, y)
    et = ExtraTreesClassifier(n_estimators=400, class_weight="balanced_subsample",
                              random_state=0, n_jobs=-1).fit(X, y)
    xgb = XGBClassifier(n_estimators=400, max_depth=5, learning_rate=0.08,
                        subsample=0.9, colsample_bytree=0.8,
                        scale_pos_weight=neg / max(pos, 1.0),
                        random_state=0, eval_metric="logloss", n_jobs=-1).fit(X, y)

    def proba(Xte):
        return (rf.predict_proba(Xte)[:, 1] + et.predict_proba(Xte)[:, 1]
                + xgb.predict_proba(Xte)[:, 1]) / 3.0
    return proba


# SafePickle-style baseline: opcode FREQUENCY features only, classic classifiers.
# No byte tokens, no allowlist, no sequence. Fix 1: run on the IDENTICAL folds and the same
# threshold protocol as ours, so "compares favorably with SafePickle" becomes a same-split
# head-to-head instead of a comparison against a foreign number.
OPHIST_IDX = [i for i, n in enumerate(FEATURE_NAMES) if n.startswith("op_")]


def _fit_safepickle(X, y):
    Xo = X[:, OPHIST_IDX]
    rf = RandomForestClassifier(n_estimators=400, class_weight="balanced_subsample",
                                random_state=0, n_jobs=-1).fit(Xo, y)
    gb = GradientBoostingClassifier(random_state=0).fit(Xo, y)

    def proba(Xte):
        Xoe = Xte[:, OPHIST_IDX]
        return (rf.predict_proba(Xoe)[:, 1] + gb.predict_proba(Xoe)[:, 1]) / 2.0
    return proba


def pick_threshold(X, y, fit_fn=None):
    """Choose the decision threshold that maximises F1, using an inner 3-fold CV on
    the TRAINING data only. The outer test fold is never seen, so this is leakage
    free."""
    fit_fn = fit_fn or _fit_ensemble
    oof = np.zeros(len(y))
    for tr, va in StratifiedKFold(3, shuffle=True, random_state=1).split(X, y):
        proba = fit_fn(X[tr], y[tr])
        oof[va] = proba(X[va])
    best_t, best_f1 = 0.5, -1.0
    for t in np.linspace(0.25, 0.75, 21):
        f1 = f1_score(y, (oof >= t).astype(int), zero_division=0)
        if f1 > best_f1:
            best_f1, best_t = f1, float(t)
    return best_t


def train_cnn_enc(seqs, scs, y, epochs=40, seed=0):
    import torch
    torch.manual_seed(seed)
    Xs, Xc = torch.tensor(seqs), torch.tensor(scs)
    yt = torch.tensor(y.astype(np.float32))
    model = _build_model()
    pos = float(y.sum())
    neg = float(len(y) - pos)
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=torch.tensor([neg / max(pos, 1.0)]))
    opt = torch.optim.Adam(model.parameters(), lr=1e-3, weight_decay=1e-4)
    n = len(y)
    bs = 32
    for _ep in range(epochs):
        model.train()
        perm = torch.randperm(n)
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            opt.zero_grad()
            loss = loss_fn(model(Xs[idx], Xc[idx]), yt[idx])
            loss.backward()
            opt.step()
    return DeepDetector(model)


def cnn_predict(det, seqs, scs):
    import torch
    det.model.eval()
    with torch.no_grad():
        logit = det.model(torch.tensor(seqs), torch.tensor(scs))
        return (torch.sigmoid(logit).numpy() >= 0.5).astype(int)


def metrics(y, p):
    spec = float(((p == 0) & (y == 0)).sum() / max((y == 0).sum(), 1))
    return {
        "precision": round(float(precision_score(y, p, zero_division=0)), 3),
        "recall": round(float(recall_score(y, p, zero_division=0)), 3),
        "f1": round(float(f1_score(y, p, zero_division=0)), 3),
        "specificity": round(spec, 3),
    }


def main():
    print("streaming real corpus (featurise + encode, discard bytes) ...", flush=True)
    t = time.time()
    Xr, seqR, scR, ry = stream_real()
    print(f"real: {len(ry)} (benign {int((ry==0).sum())}, malicious {int((ry==1).sum())}) in {time.time()-t:.0f}s", flush=True)
    print("streaming synthetic ...", flush=True)
    t = time.time()
    Xs, seqS, scS, sy = stream_synth()
    print(f"synthetic: {len(sy)} in {time.time()-t:.0f}s", flush=True)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=0)
    ml_pred = np.zeros(len(ry), int)
    cnn_pred = np.zeros(len(ry), int)
    sp_pred = np.zeros(len(ry), int)
    thresholds, sp_thresholds = [], []
    fold_f1 = {"ML (ours)": [], "CNN (ours)": [], "SafePickle (reproduced)": []}
    for k, (tr, te) in enumerate(skf.split(Xr, ry)):
        t0 = time.time()
        Xtr = np.vstack([Xs, Xr[tr]])
        ytr = np.concatenate([sy, ry[tr]])
        thr = pick_threshold(Xtr, ytr)          # inner CV, leakage-free
        proba = _fit_ensemble(Xtr, ytr)
        ml_pred[te] = (proba(Xr[te]) >= thr).astype(int)
        thresholds.append(round(thr, 3))
        seqtr = np.vstack([seqS, seqR[tr]])
        sctr = np.vstack([scS, scR[tr]])
        det = train_cnn_enc(seqtr, sctr, ytr)
        cnn_pred[te] = cnn_predict(det, seqR[te], scR[te])
        # Fix 1: SafePickle-repro on the SAME fold, same threshold protocol
        thr_sp = pick_threshold(Xtr, ytr, _fit_safepickle)
        sp_pred[te] = (_fit_safepickle(Xtr, ytr)(Xr[te]) >= thr_sp).astype(int)
        sp_thresholds.append(round(thr_sp, 3))
        # Fix 3: per-fold F1 so we can report mean, std and a confidence interval
        fold_f1["ML (ours)"].append(round(float(f1_score(ry[te], ml_pred[te], zero_division=0)), 3))
        fold_f1["CNN (ours)"].append(round(float(f1_score(ry[te], cnn_pred[te], zero_division=0)), 3))
        fold_f1["SafePickle (reproduced)"].append(round(float(f1_score(ry[te], sp_pred[te], zero_division=0)), 3))
        print(f"fold {k+1}/5 thr={thr:.2f} sp_thr={thr_sp:.2f} in {time.time()-t0:.0f}s", flush=True)

    def mean_std(vals):
        return {"mean": round(float(np.mean(vals)), 3), "std": round(float(np.std(vals)), 3)}

    def bootstrap_ci(y, p, n=2000, seed=0):
        """Non-parametric bootstrap 95% CI on pooled out-of-fold F1 (Fix 3)."""
        rng = np.random.default_rng(seed)
        idx = np.arange(len(y))
        f1s = []
        for _ in range(n):
            s = rng.choice(idx, len(idx), replace=True)
            f1s.append(f1_score(y[s], p[s], zero_division=0))
        lo, hi = np.percentile(f1s, [2.5, 97.5])
        return [round(float(lo), 3), round(float(hi), 3)]

    out = {
        "n_real": int(len(ry)),
        "n_benign": int((ry == 0).sum()),
        "n_malicious": int((ry == 1).sum()),
        "protocol": "stratified 5-fold CV on real corpus, synthetic always in training, real test folds held out, threshold tuned by inner CV. SafePickle-repro uses opcode-frequency features only on the identical folds.",
        "ml_thresholds": thresholds,
        "sp_thresholds": sp_thresholds,
        "ML (ours)": metrics(ry, ml_pred),
        "CNN (ours)": metrics(ry, cnn_pred),
        "SafePickle (reproduced, same split)": metrics(ry, sp_pred),
        "per_fold_f1": fold_f1,
        "f1_mean_std": {kk: mean_std(vv) for kk, vv in fold_f1.items()},
        "f1_ci95_bootstrap": {
            "ML (ours)": bootstrap_ci(ry, ml_pred),
            "CNN (ours)": bootstrap_ci(ry, cnn_pred),
            "SafePickle (reproduced)": bootstrap_ci(ry, sp_pred),
        },
    }
    print(json.dumps(out, indent=2), flush=True)
    os.makedirs("/content/results", exist_ok=True)
    with open(RESULTS, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"saved {RESULTS}", flush=True)


if __name__ == "__main__":
    main()
