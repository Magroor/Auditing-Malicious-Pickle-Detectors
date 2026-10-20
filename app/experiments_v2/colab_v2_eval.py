"""Robustness v2, step 3: de-duplicated, grouped, leakage-free evaluation of the FROZEN v1
detectors against a faithful SafePickle reproduction, with per-file predictions and an error
analysis. Implements PREREGISTRATION.md (fixed 2026-10-02). Colab only.

Safety: every file is read as raw bytes and analysed statically with pickletools. Nothing is ever
deserialised: no pickle.load, pickle.loads or torch.load is called on any sample. No sample bytes
are written anywhere, only numeric features and static summaries.

Stages (each one checkpoints to /content/results and, if mounted, Google Drive):
  1. featurise every real file once (v1 features, raw opcode counts, full canonical sequence,
     error-analysis variables, SHA-256 and structural group id)
  2. exact de-duplication, near-duplicate groups, locked 25 % test split (NOT evaluated here)
  3. 5 x 5 repeated StratifiedGroupKFold on the development set: ML, CNN, SP-RF, SP-CB, SP-AE,
     SP-style, plus the two SP-RF sensitivity variants
  4. pre-registered statistics on repetition 0, corrected t-test over all 25 folds
  5. error analysis on development-set out-of-fold predictions

Usage on Colab:  !python /content/colab_v2_eval.py            (all stages, 5 repetitions)
                 !python /content/colab_v2_eval.py --reps 1   (quick check)
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import logging
import os
import pickletools
import sys
import time
import zipfile

logging.disable(logging.CRITICAL)
sys.path.insert(0, "/content")

import numpy as np                                                          # noqa: E402
from scipy.stats import binomtest, t as student_t                           # noqa: E402
from sklearn.ensemble import RandomForestClassifier                         # noqa: E402
from sklearn.metrics import f1_score, roc_auc_score                         # noqa: E402
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold   # noqa: E402

import picklescan_ml.features as F                                          # noqa: E402
try:  # training-only import; the verdict-only reproduction does not need it
    from picklescan_ml.deep import (MAXLEN, SCALAR_KEYS, _SCALAR_IDX,           # noqa: E402
                                    opcode_sequence, scalar_features)
except ImportError:
    MAXLEN = None
    SCALAR_KEYS = None
    _SCALAR_IDX = None
    opcode_sequence = None
    scalar_features = None
from picklescan_ml.scan import archive_members                              # noqa: E402
from picklescan_ml.semantic import semantic_canonicalize                    # noqa: E402
from safepickle_colab import collect_files                                  # noqa: E402
# The v1 detectors are imported, not re-written, so they are exactly the frozen v1 code.
from safepickle_train_eval import (_fit_ensemble, _fit_safepickle,          # noqa: E402
                                   pick_threshold, train_cnn_enc)
try:  # training-only import; the verdict-only reproduction does not need it
    from train_deep import augmented_training, augmented_training_hardened       # noqa: E402
except ImportError:
    augmented_training = None
    augmented_training_hardened = None

# v2 detector (semantic-input CNN + monotone evidence + frequency branch). Guarded
# so a failure to import it can never break the frozen v1/SafePickle evaluation.
try:
    from picklescan_ml.deep_v2 import (FREQ_DIM as V2_FREQ, MAXLEN as V2_MAXLEN,  # noqa: E402
                                       cnn_v2_proba, encode as v2_encode,
                                       train_cnn_v2_enc)
    V2_OK = True
except Exception:                                                           # pragma: no cover
    V2_OK = False

# The CNNv2 wiring in THIS harness builds v2 inputs from the cached sem_* arrays,
# which predates the v2 learned-gate encoding (token ids + module buckets are not
# in the cache). Until stage1 is extended to cache those, CNNv2 is evaluated via
# experiments_v2/colab_headtohead.py (which re-encodes from bytes). Set True only
# after stage1 caches S2/F2/T2/M2/D2.
V2_READY = False

DATA = os.environ.get("V2_DATA", "/content/safepickle")
OUT = os.environ.get("V2_OUT", "/content/results/v2")
DRIVE = os.environ.get("V2_DRIVE", "/content/drive/MyDrive/colab_ckpts/v2")
MAX_FILE = 80 * 1024 * 1024
LOCK_SEED = 20261002
GRID = np.linspace(0.25, 0.75, 21)
SEQ_STORE_CAP = 100_000          # full canonical sequence kept for v2, capped per file
N_OPS = len(F.OPCODE_NAMES)


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def persist(name, obj=None, npz=None):
    """Write a result to OUT and mirror it to Drive when Drive is mounted."""
    os.makedirs(OUT, exist_ok=True)
    targets = [OUT] + ([DRIVE] if os.path.isdir("/content/drive/MyDrive") else [])
    for d in targets:
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        if npz is not None:
            np.savez_compressed(p, **npz)
        else:
            with open(p, "w", encoding="utf-8") as fh:
                json.dump(obj, fh, indent=2)


# ----------------------------------------------------------------------------- stage 1
def raw_opcodes(inner: bytes):
    """Opcode names WITHOUT canonicalisation (SafePickle reads plain pickletools output),
    with the same size and opcode caps as the v1 extractor. Also returns the STOP position."""
    names, parse_error, stop_pos = [], False, None
    if not inner or len(inner) > F.MAX_STREAM_BYTES:
        return names, True, None
    try:
        for op, _arg, pos in pickletools.genops(inner):
            names.append(op.name)
            if op.name == "STOP":
                stop_pos = pos
            if len(names) >= F.MAX_OPS:
                parse_error = True
                break
    except Exception:
        parse_error = True
    return names, parse_error, stop_pos


def count_streams(inner: bytes, max_streams: int = 50) -> int:
    """How many complete pickle streams sit back to back in the inner bytes. A payload in a
    second stream after the first STOP is invisible to a parser that stops at STOP."""
    if not inner or len(inner) > F.MAX_STREAM_BYTES:
        return 0
    bio, n, total_ops = io.BytesIO(inner), 0, 0
    while bio.tell() < len(inner) and n < max_streams:
        last = None
        try:
            for op, _arg, pos in pickletools.genops(bio):
                last = (op.name, pos)
                total_ops += 1
                if total_ops >= F.MAX_OPS:
                    return n
        except Exception:
            break
        if last is None or last[0] != "STOP":
            break
        n += 1
        bio.seek(last[1] + 1)
    return n


def first_nonallowlisted_index(ops) -> int:
    """Opcode index (in the canonical stream the CNN reads) of the first import outside the
    allowlist, or -1. Mirrors features.extract_imports."""
    recent = []
    for i, (name, arg, _p) in enumerate(ops):
        if name in F.STRING_OPCODES and isinstance(arg, str):
            recent.append(arg)
            recent = recent[-8:]
        elif name in ("GLOBAL", "INST") and isinstance(arg, str):
            parts = arg.replace("\n", " ").split()
            mod = parts[0] if parts else ""
            nm = parts[1] if len(parts) > 1 else ""
            if not F._is_allowlisted(mod, nm):
                return i
        elif name == "STACK_GLOBAL" and len(recent) >= 2:
            if not F._is_allowlisted(recent[-2], recent[-1]):
                return i
    return -1


SEM_KEYS = ["n_members", "broken", "n_streams", "n_ops_raw", "n_effects", "n_calls", "n_dynamic_imports",
            "n_static_imports", "n_nonallow_imports", "n_persid", "n_dead_nodes", "dead_fraction", "n_emitted"]


def semantic_encode(inner: bytes, data: bytes):
    """v2 input, cached now so the v2 run needs no second download: the semantic canonical
    stream (effects view) of the main pickle and of every extra pickle member of an archive,
    concatenated, plus summed statistics. Static only, see picklescan_ml/semantic.py."""
    members = [inner] + [b for _n, b in archive_members(data)]
    toks, agg = [], {k: 0.0 for k in SEM_KEYS}
    agg["n_members"] = float(len(members))
    for m in members:
        ops, st = semantic_canonicalize(m)
        toks.extend(F.OPCODE_INDEX[n] + 1 for n, _a, _p in ops if n in F.OPCODE_INDEX)
        for k in SEM_KEYS[1:]:
            agg[k] += float(st.get(k, 0))
    agg["dead_fraction"] = agg["n_dead_nodes"] / max(agg["n_dead_nodes"] + agg["n_emitted"], 1.0)
    return np.asarray(toks[:SEQ_STORE_CAP], np.uint8), np.array([agg[k] for k in SEM_KEYS], np.float32)


def encode_file(data: bytes):
    """All per-file numbers. v1 features come from features.featurize exactly as in v1."""
    vec, info = F.featurize(data)
    ops = info["ops"]                                   # canonical ops, as v1 sees them
    idx = [F.OPCODE_INDEX[n] + 1 for n, _a, _p in ops if n in F.OPCODE_INDEX]
    seq = np.zeros(MAXLEN, np.int64)
    seq[:min(len(idx), MAXLEN)] = idx[:MAXLEN]
    sc = vec[_SCALAR_IDX].astype(np.float32).copy()
    sc[SCALAR_KEYS.index("n_ops")] = np.log1p(sc[SCALAR_KEYS.index("n_ops")])
    sc[SCALAR_KEYS.index("stream_len")] = np.log1p(sc[SCALAR_KEYS.index("stream_len")])

    inner = F.unwrap(data)
    rnames, rerr, stop_pos = raw_opcodes(inner)
    counts = np.zeros(N_OPS, np.float32)
    for n in rnames:
        counts[F.OPCODE_INDEX[n]] += 1.0

    n_pkl = 0
    if data[:2] == b"PK":
        try:
            n_pkl = sum(1 for n in zipfile.ZipFile(io.BytesIO(data)).namelist() if n.endswith(".pkl"))
        except Exception:
            n_pkl = -1
    container = "zip" if data[:2] == b"PK" else ("pickle" if rnames else "other")
    sha = hashlib.sha256(data).hexdigest()
    globs = sorted({f"{m}.{n}" for m, n in info["imports"]})
    if info["parse_error"] or not ops:
        group = "raw:" + sha
    else:
        sig = "|".join(n for n, _a, _p in ops) + "#" + "|".join(globs)
        group = "struct:" + hashlib.sha256(sig.encode("utf-8", "replace")).hexdigest()
    fna = first_nonallowlisted_index(ops)
    meta = {
        "sha256": sha, "group": group, "container": container, "n_pkl_members": n_pkl,
        "file_bytes": len(data), "inner_bytes": len(inner),
        "trailing_after_stop": (len(inner) - stop_pos - 1) if stop_pos is not None else -1,
        "n_streams": count_streams(inner), "proto": info["proto_version"],
        "n_ops_raw": len(rnames), "n_ops_canon": len(ops), "parse_error": int(info["parse_error"]),
        "first_nonallow_idx": fna, "nonallow_beyond_window": int(fna >= MAXLEN),
        "byte_tokens": ";".join(info["byte_tokens"]), "n_byte_tokens": len(info["byte_tokens"]),
        "n_nonallowlisted": len(info["nonallowlisted_globals"]),
        "picklescan_dangerous": info["picklescan_dangerous"],
    }
    full = np.asarray(idx[:SEQ_STORE_CAP], np.uint8)
    sem_seq, sem_stats = semantic_encode(inner, data)
    meta.update({"sem_" + k: float(v) for k, v in zip(SEM_KEYS, sem_stats)})
    return vec, seq, sc, counts, full, meta, sem_seq, sem_stats


def stage1(force=False):
    cache = os.path.join(OUT, "features_cache.npz")
    if os.path.exists(cache) and not force:
        log("stage 1: using cached features")
        z = np.load(cache, allow_pickle=False)
        meta = json.load(open(os.path.join(OUT, "file_meta.json"), encoding="utf-8"))
        return {k: z[k] for k in z.files}, meta

    items = collect_files(DATA)
    log(f"stage 1: {len(items)} files found")
    X, S, C, R, Y, FULL, meta, SEM, SEMST = [], [], [], [], [], [], [], [], []
    skipped = {"too_large": 0, "read_error": 0}
    checked = 0
    for i, (path, lab) in enumerate(items):
        try:
            if os.path.getsize(path) > MAX_FILE:
                skipped["too_large"] += 1
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            v, seq, sc, cnt, full, m, sem, semst = encode_file(data)
            if checked < 20:            # identity check against the v1 encoders
                assert np.array_equal(seq, opcode_sequence(data)), path
                assert np.allclose(sc, scalar_features(data)), path
                checked += 1
        except AssertionError:
            raise
        except Exception:
            skipped["read_error"] += 1
            continue
        m["path"] = os.path.relpath(path, DATA)
        m["label"] = int(lab)
        X.append(v); S.append(seq); C.append(sc); R.append(cnt); Y.append(lab); FULL.append(full)
        SEM.append(sem); SEMST.append(semst)
        meta.append(m)
        del data
        if i % 100 == 0:
            log(f"  real {i}/{len(items)}")
    log(f"  usable {len(Y)}, skipped {skipped}")

    log("stage 1: synthetic training set (v1 augmented_training)")
    sb, sy = augmented_training()
    XS, SS, CS, RS, SEMS, SEMSTS = [], [], [], [], [], []
    for b in sb:
        v, seq, sc, cnt, _full, _m, sem, semst = encode_file(b)
        XS.append(v); SS.append(seq); CS.append(sc); RS.append(cnt); SEMS.append(sem); SEMSTS.append(semst)

    offs = np.cumsum([0] + [len(f) for f in FULL]).astype(np.int64)
    arrays = {
        "X": np.vstack(X), "S": np.stack(S), "C": np.stack(C), "R": np.stack(R), "Y": np.array(Y),
        "XS": np.vstack(XS), "SS": np.stack(SS), "CS": np.stack(CS), "RS": np.stack(RS),
        "YS": np.asarray(sy), "full_seq": np.concatenate(FULL) if FULL else np.zeros(0, np.uint8),
        "full_off": offs,
        "sem_seq": np.concatenate(SEM) if SEM else np.zeros(0, np.uint8),
        "sem_off": np.cumsum([0] + [len(f) for f in SEM]).astype(np.int64),
        "sem_stats": np.stack(SEMST),
        "sem_seq_S": np.concatenate(SEMS) if SEMS else np.zeros(0, np.uint8),
        "sem_off_S": np.cumsum([0] + [len(f) for f in SEMS]).astype(np.int64),
        "sem_stats_S": np.stack(SEMSTS),
    }
    persist("features_cache.npz", npz=arrays)
    persist("file_meta.json", meta)
    persist("stage1_skipped.json", skipped)
    return arrays, meta


# ----------------------------------------------------------------------------- stage 2
def stage2(A, meta):
    y = A["Y"]
    by_hash = {}
    for i, m in enumerate(meta):
        by_hash.setdefault(m["sha256"], []).append(i)
    keep, dup_removed, conflict_dropped = [], 0, 0
    for _h, idxs in by_hash.items():
        labs = {int(y[i]) for i in idxs}
        if len(labs) > 1:
            conflict_dropped += len(idxs)
            continue
        keep.append(idxs[0])
        dup_removed += len(idxs) - 1
    keep = np.array(sorted(keep))
    groups = np.array([meta[i]["group"] for i in keep])
    yk = y[keep]
    sgkf = StratifiedGroupKFold(n_splits=4, shuffle=True, random_state=LOCK_SEED)
    _dev_pos, lock_pos = next(sgkf.split(np.zeros(len(keep)), yk, groups))
    lock = keep[lock_pos]
    dev = np.setdiff1d(keep, lock)
    manifest = sorted(meta[i]["sha256"] for i in lock)
    persist("locked_test_manifest.json", {"seed": LOCK_SEED, "n": len(manifest), "sha256": manifest})
    mhash = hashlib.sha256(json.dumps(manifest).encode()).hexdigest()
    sizes = {}
    for g in groups:
        sizes[g] = sizes.get(g, 0) + 1
    gs = np.array(list(sizes.values()))
    summary = {
        "n_files_featurised": int(len(y)), "exact_duplicates_removed": int(dup_removed),
        "conflicting_label_files_dropped": int(conflict_dropped), "n_unique": int(len(keep)),
        "n_unique_benign": int((y[keep] == 0).sum()), "n_unique_malicious": int((y[keep] == 1).sum()),
        "n_groups": int(len(gs)), "groups_size_gt1": int((gs > 1).sum()), "largest_group": int(gs.max()),
        "files_in_shared_groups": int(gs[gs > 1].sum()),
        "dev": {"n": int(len(dev)), "benign": int((y[dev] == 0).sum()), "malicious": int((y[dev] == 1).sum())},
        "locked": {"n": int(len(lock)), "benign": int((y[lock] == 0).sum()), "malicious": int((y[lock] == 1).sum()),
                   "manifest_sha256": mhash},
    }
    log("stage 2: " + json.dumps(summary))
    persist("stage2_split.json", summary)
    return dev, lock, summary


# ----------------------------------------------------------------------------- stage 3
def cnn_proba(det, seqs, scs):
    import torch
    det.model.eval()
    with torch.no_grad():
        return torch.sigmoid(det.model(torch.tensor(seqs), torch.tensor(scs))).numpy()


def best_threshold(y, p):
    best_t, best_f = 0.5, -1.0
    for t in GRID:
        f = f1_score(y, (p >= t).astype(int), zero_division=0)
        if f > best_f:
            best_f, best_t = f, float(t)
    return best_t


def cnn_inner_threshold(seqs, scs, y, seed):
    oof = np.zeros(len(y))
    for tr, va in StratifiedKFold(3, shuffle=True, random_state=1).split(seqs, y):
        oof[va] = cnn_proba(train_cnn_enc(seqs[tr], scs[tr], y[tr], seed=seed), seqs[va], scs[va])
    return best_threshold(y, oof)


def _v2_from(sem_seq, sem_off, sem_stats, C):
    """Build v2 (seq ids, evidence, frequency) arrays from the cached semantic
    arrays. seq ids and the frequency histogram come from the semantic canonical
    stream (padding-invariant); the evidence counts reuse the v1 scalars for the
    byte-token and parse-error entries and the semantic stats for the rest."""
    n = len(sem_off) - 1
    S = np.zeros((n, V2_MAXLEN), np.int64)
    Fh = np.zeros((n, V2_FREQ), np.float32)
    for i in range(n):
        toks = sem_seq[sem_off[i]:sem_off[i + 1]].astype(np.int64)
        m = min(len(toks), V2_MAXLEN)
        S[i, :m] = toks[:m]
        for t in toks:
            if 1 <= t <= V2_FREQ:
                Fh[i, t - 1] += 1.0
        s = Fh[i].sum()
        if s > 0:
            Fh[i] /= s
    nnon = sem_stats[:, SEM_KEYS.index("n_nonallow_imports")]
    ndead = sem_stats[:, SEM_KEYS.index("n_dead_nodes")]
    nbyte = C[:, SCALAR_KEYS.index("n_byte_tokens")]
    perr = C[:, SCALAR_KEYS.index("parse_error")]
    E = np.stack([nbyte, nnon, np.log1p(ndead), perr,
                  (nbyte > 0).astype(np.float32), (nnon > 0).astype(np.float32)],
                 axis=1).astype(np.float32)
    return S, E, Fh


def build_v2_arrays(A):
    """Attach v2 inputs to A, reusing the cached semantic arrays (no re-download),
    and append the hardened gadget families to the synthetic training side so the
    Colab v2 model matches the hardened local model."""
    A["S2"], A["E2"], A["F2"] = _v2_from(A["sem_seq"], A["sem_off"], A["sem_stats"], A["C"])
    S2S, E2S, F2S = _v2_from(A["sem_seq_S"], A["sem_off_S"], A["sem_stats_S"], A["CS"])
    base_tb, _ = augmented_training()
    hard_tb, _ = augmented_training_hardened()
    extra = hard_tb[len(base_tb):]
    if extra:
        es, ee, ef = zip(*(v2_encode(b) for b in extra))
        S2S = np.vstack([S2S, np.stack(es)])
        E2S = np.vstack([E2S, np.stack(ee)])
        F2S = np.vstack([F2S, np.stack(ef)])
        A["YS2"] = np.concatenate([A["YS"], np.ones(len(extra), int)])
    else:
        A["YS2"] = A["YS"]
    A["S2S"], A["E2S"], A["F2S"] = S2S, E2S, F2S
    log(f"v2 arrays: real {A['S2'].shape}, synth {A['S2S'].shape} (+{len(extra)} hardened gadgets)")


def cnn_v2_inner_threshold(S2, E2, F2, y, seed):
    oof = np.zeros(len(y))
    for tr, va in StratifiedKFold(3, shuffle=True, random_state=1).split(S2, y):
        det = train_cnn_v2_enc(S2[tr], E2[tr], F2[tr], y[tr], seed=seed)
        oof[va] = cnn_v2_proba(det, S2[va], E2[va], F2[va])
    return best_threshold(y, oof)


def freq(counts):
    tot = counts.sum(1, keepdims=True)
    return np.divide(counts, tot, out=np.zeros_like(counts), where=tot > 0)


def fit_sp_rf(Ftr, ytr, seed):
    keep = Ftr.sum(0) > 0          # all-zero columns of the training fold dropped
    rf = RandomForestClassifier(random_state=seed, n_jobs=-1).fit(Ftr[:, keep], ytr)
    return lambda Fte: rf.predict_proba(Fte[:, keep])[:, 1]


def fit_sp_cb(Ftr, ytr, seed):
    from catboost import CatBoostClassifier
    keep = Ftr.sum(0) > 0
    cb = CatBoostClassifier(verbose=0, random_seed=seed, thread_count=-1).fit(Ftr[:, keep], ytr)
    return lambda Fte: cb.predict_proba(Fte[:, keep])[:, 1]


def fit_sp_ae(Ftr, ytr, seed):
    """Autoencoder on benign training files, alarm when reconstruction error exceeds the 95th
    percentile of benign training error. Architecture is our choice (paper gives none)."""
    import torch
    import torch.nn as nn
    torch.manual_seed(seed)
    keep = Ftr.sum(0) > 0
    Xb = torch.tensor(Ftr[ytr == 0][:, keep], dtype=torch.float32)
    d = Xb.shape[1]
    ae = nn.Sequential(nn.Linear(d, 32), nn.ReLU(), nn.Linear(32, 8), nn.ReLU(),
                       nn.Linear(8, 32), nn.ReLU(), nn.Linear(32, d))
    opt = torch.optim.Adam(ae.parameters(), lr=1e-3)
    for _ep in range(100):
        perm = torch.randperm(len(Xb))
        for i in range(0, len(Xb), 32):
            b = Xb[perm[i:i + 32]]
            opt.zero_grad()
            loss = ((ae(b) - b) ** 2).mean()
            loss.backward()
            opt.step()
    ae.eval()

    def err(Fx):
        with torch.no_grad():
            x = torch.tensor(Fx[:, keep], dtype=torch.float32)
            return ((ae(x) - x) ** 2).mean(1).numpy()
    thr = float(np.percentile(err(Ftr[ytr == 0]), 95))
    return err, thr


MODELS = ["ML", "CNN", "CNN@0.5", "SP-RF", "SP-CB", "SP-AE", "SP-style", "SP-RF-tuned", "SP-RF+synth"]
if V2_OK and V2_READY:
    MODELS += ["CNNv2", "CNNv2@0.5"]
# Metadata-only baseline (PREREGISTRATION amendment 2026-10-04): it never reads opcodes, so it
# shows how much of every detector's score file shape alone explains. Filled by add_meta(), which
# also back-fills checkpoints written before the baseline existed, on the identical folds.
MODELS += ["META"]


def meta_vec(m):
    """Container, protocol, sizes and member counts, as in ned2/analysis/matched_benign._meta_vec."""
    v = [float(m["container"] == c) for c in ("zip", "pickle", "other")]
    v += [float(m.get("proto") == p) for p in (0, 2, 3, 4, 5)]
    v += [np.log1p(m["file_bytes"]), np.log1p(m.get("inner_bytes", m["file_bytes"])),
          float(m.get("n_pkl_members") or 0), float(m.get("n_streams") or 0),
          float(m.get("trailing_after_stop") or 0)]
    return v


def add_meta(A, meta, dev, allres):
    from sklearn.linear_model import LogisticRegression
    y, groups = A["Y"], np.array(A["groups"])
    M = np.array([meta_vec(m) for m in meta], dtype=float)
    for rep, r in allres.items():
        if "META" in r["prob"] and all(r["prob"]["META"][i] is not None for i in dev):
            continue
        r["prob"]["META"], r["pred"]["META"] = [None] * len(y), [None] * len(y)
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=int(rep))
        for k, (trp, tep) in enumerate(sgkf.split(np.zeros(len(dev)), y[dev], groups[dev])):
            tr, te = dev[trp], dev[tep]
            fold = r["folds"][k]
            assert fold["n_test"] == len(te) and fold["n_train_real"] == len(tr), "fold mismatch"
            p = LogisticRegression(max_iter=5000, random_state=int(rep)).fit(M[tr], y[tr]).predict_proba(M[te])[:, 1]
            d = (p >= 0.5).astype(int)
            for j, i in enumerate(te):
                r["prob"]["META"][i], r["pred"]["META"][i] = float(p[j]), int(d[j])
            fold["thresholds"]["META"] = 0.5
            fold["f1"]["META"] = round(float(f1_score(y[te], d, zero_division=0)), 4)
        persist(f"cv_rep{rep}.json", r)
        log(f"  rep {rep}: metadata baseline added")
    return allres


def run_fold(A, tr, te, seed):
    """Train every detector on the training fold, return probabilities and predictions on te."""
    Xr, Sr, Cr, Rr, yr = A["X"], A["S"], A["C"], A["R"], A["Y"]
    XS, SS, CS, RS, yS = A["XS"], A["SS"], A["CS"], A["RS"], A["YS"]
    out, t0 = {}, time.time()
    Xtr = np.vstack([XS, Xr[tr]])
    ytr = np.concatenate([yS, yr[tr]])
    thr = pick_threshold(Xtr, ytr)
    p = _fit_ensemble(Xtr, ytr)(Xr[te])
    out["ML"] = (p, (p >= thr).astype(int), thr)

    Str, Ctr = np.vstack([SS, Sr[tr]]), np.vstack([CS, Cr[tr]])
    cthr = cnn_inner_threshold(Str, Ctr, ytr, seed)
    p = cnn_proba(train_cnn_enc(Str, Ctr, ytr, seed=seed), Sr[te], Cr[te])
    out["CNN"] = (p, (p >= cthr).astype(int), cthr)
    out["CNN@0.5"] = (p, (p >= 0.5).astype(int), 0.5)

    thr_s = pick_threshold(Xtr, ytr, _fit_safepickle)
    p = _fit_safepickle(Xtr, ytr)(Xr[te])
    out["SP-style"] = (p, (p >= thr_s).astype(int), thr_s)

    Ftr, Fte, yrt = freq(Rr[tr]), freq(Rr[te]), yr[tr]
    p = fit_sp_rf(Ftr, yrt, seed)(Fte)
    out["SP-RF"] = (p, (p >= 0.5).astype(int), 0.5)
    p = fit_sp_cb(Ftr, yrt, seed)(Fte)
    out["SP-CB"] = (p, (p >= 0.5).astype(int), 0.5)
    err, athr = fit_sp_ae(Ftr, yrt, seed)
    p = err(Fte)
    out["SP-AE"] = (p, (p > athr).astype(int), athr)

    oof = np.zeros(len(tr))
    for itr, iva in StratifiedKFold(3, shuffle=True, random_state=1).split(Ftr, yrt):
        oof[iva] = fit_sp_rf(Ftr[itr], yrt[itr], seed)(Ftr[iva])
    t_rf = best_threshold(yrt, oof)
    p = out["SP-RF"][0]
    out["SP-RF-tuned"] = (p, (p >= t_rf).astype(int), t_rf)
    Fsyn = np.vstack([freq(RS), Ftr])
    p = fit_sp_rf(Fsyn, np.concatenate([yS, yrt]), seed)(Fte)
    out["SP-RF+synth"] = (p, (p >= 0.5).astype(int), 0.5)

    if V2_OK and V2_READY:
        S2tr = np.vstack([A["S2S"], A["S2"][tr]])
        E2tr = np.vstack([A["E2S"], A["E2"][tr]])
        F2tr = np.vstack([A["F2S"], A["F2"][tr]])
        y2tr = np.concatenate([A["YS2"], yr[tr]])
        c2 = cnn_v2_inner_threshold(S2tr, E2tr, F2tr, y2tr, seed)
        det2 = train_cnn_v2_enc(S2tr, E2tr, F2tr, y2tr, seed=seed)
        p2 = cnn_v2_proba(det2, A["S2"][te], A["E2"][te], A["F2"][te])
        out["CNNv2"] = (p2, (p2 >= c2).astype(int), c2)
        out["CNNv2@0.5"] = (p2, (p2 >= 0.5).astype(int), 0.5)
    return out, time.time() - t0


def stage3(A, dev, reps):
    y = A["Y"]
    groups = np.array(A["groups"])
    allres = {}
    for rep in range(reps):
        ck = os.path.join(OUT, f"cv_rep{rep}.json")
        if os.path.exists(ck):
            allres[rep] = json.load(open(ck, encoding="utf-8"))
            log(f"stage 3: rep {rep} loaded from checkpoint")
            continue
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=rep)
        prob = {m: [None] * len(y) for m in MODELS}
        pred = {m: [None] * len(y) for m in MODELS}
        folds = []
        for k, (trp, tep) in enumerate(sgkf.split(np.zeros(len(dev)), y[dev], groups[dev])):
            tr, te = dev[trp], dev[tep]
            res, sec = run_fold(A, tr, te, seed=rep)
            fold = {"fold": k, "n_train_real": int(len(tr)), "n_test": int(len(te)), "seconds": round(sec, 1),
                    "thresholds": {}, "f1": {}}
            for m, (p, d, th) in res.items():
                for j, i in enumerate(te):
                    prob[m][i] = float(p[j])
                    pred[m][i] = int(d[j])
                fold["thresholds"][m] = round(float(th), 6)
                fold["f1"][m] = round(float(f1_score(y[te], d, zero_division=0)), 4)
            folds.append(fold)
            log(f"  rep {rep} fold {k + 1}/5 {sec:.0f}s  " +
                " ".join(f"{m}={fold['f1'][m]:.3f}" for m in ("ML", "CNN", "SP-RF")))
        allres[rep] = {"folds": folds, "prob": prob, "pred": pred}
        persist(f"cv_rep{rep}.json", allres[rep])
    return allres


# ----------------------------------------------------------------------------- stage 4
def confusion(y, p):
    return {"TP": int(((p == 1) & (y == 1)).sum()), "FP": int(((p == 1) & (y == 0)).sum()),
            "TN": int(((p == 0) & (y == 0)).sum()), "FN": int(((p == 0) & (y == 1)).sum())}


def summary_metrics(y, p, s):
    c = confusion(y, p)
    prec = c["TP"] / max(c["TP"] + c["FP"], 1)
    rec = c["TP"] / max(c["TP"] + c["FN"], 1)
    out = dict(c)
    out.update({"precision": round(prec, 4), "recall": round(rec, 4),
                "f1": round(f1_score(y, p, zero_division=0), 4),
                "specificity": round(c["TN"] / max(c["TN"] + c["FP"], 1), 4)})
    try:
        out["auc"] = round(float(roc_auc_score(y, s)), 4)
    except ValueError:
        out["auc"] = None
    return out


def boot_delta_f1(y, pa, pb, n=10_000, seed=0):
    """Paired stratified bootstrap of F1(a) - F1(b). Class sizes fixed per resample."""
    rng = np.random.default_rng(seed)
    pos, neg = np.where(y == 1)[0], np.where(y == 0)[0]
    tpa, fna = (pa == 1) & (y == 1), (pa == 0) & (y == 1)
    tpb, fnb = (pb == 1) & (y == 1), (pb == 0) & (y == 1)
    fpa, fpb = (pa == 1) & (y == 0), (pb == 1) & (y == 0)
    deltas = np.empty(n)
    for b in range(n):
        ip = pos[rng.integers(0, len(pos), len(pos))]
        ineg = neg[rng.integers(0, len(neg), len(neg))]
        TPa, FNa, FPa = tpa[ip].sum(), fna[ip].sum(), fpa[ineg].sum()
        TPb, FNb, FPb = tpb[ip].sum(), fnb[ip].sum(), fpb[ineg].sum()
        fa = 2 * TPa / max(2 * TPa + FPa + FNa, 1)
        fb = 2 * TPb / max(2 * TPb + FPb + FNb, 1)
        deltas[b] = fa - fb
    lo, hi = np.percentile(deltas, [2.5, 97.5])
    p = 2 * min((deltas <= 0).mean(), (deltas >= 0).mean())
    return {"delta_f1": round(float(f1_score(y, pa) - f1_score(y, pb)), 4),
            "ci95": [round(float(lo), 4), round(float(hi), 4)], "p_two_sided": round(float(min(p, 1.0)), 5)}


def boot_noninferiority(y, pa, pb, margin_f1=-0.02, margin_spec=-0.005, n=10_000, seed=0):
    """PREREGISTRATION section 9.1: a is non-inferior to b if the one-sided 95 % lower bound of the
    paired stratified bootstrap of F1(a) - F1(b) is above margin_f1 (same rule for specificity).
    p = share of resamples at or below the margin (one-sided bootstrap p)."""
    rng = np.random.default_rng(seed)
    pos, neg = np.where(y == 1)[0], np.where(y == 0)[0]
    tpa, tpb = (pa == 1) & (y == 1), (pb == 1) & (y == 1)
    fpa, fpb = (pa == 1) & (y == 0), (pb == 1) & (y == 0)
    df, ds = np.empty(n), np.empty(n)
    for b in range(n):
        ip = pos[rng.integers(0, len(pos), len(pos))]
        ineg = neg[rng.integers(0, len(neg), len(neg))]
        TPa, TPb, FPa, FPb = tpa[ip].sum(), tpb[ip].sum(), fpa[ineg].sum(), fpb[ineg].sum()
        FNa, FNb = len(ip) - TPa, len(ip) - TPb
        df[b] = 2 * TPa / max(2 * TPa + FPa + FNa, 1) - 2 * TPb / max(2 * TPb + FPb + FNb, 1)
        ds[b] = (FPb - FPa) / len(ineg)                   # spec(a) - spec(b)
    out = {}
    for name, d, margin in (("f1", df, margin_f1), ("specificity", ds, margin_spec)):
        lb = float(np.percentile(d, 5))
        out[name] = {"lower_bound_95_one_sided": round(lb, 4), "margin": margin,
                     "p_one_sided": round(float((d <= margin).mean()), 5), "non_inferior": bool(lb > margin)}
    return out


def boot_auc(y, sa, sb, n=2000, seed=0):
    rng = np.random.default_rng(seed)
    pos, neg = np.where(y == 1)[0], np.where(y == 0)[0]
    d = []
    for _ in range(n):
        idx = np.concatenate([pos[rng.integers(0, len(pos), len(pos))], neg[rng.integers(0, len(neg), len(neg))]])
        d.append(roc_auc_score(y[idx], sa[idx]) - roc_auc_score(y[idx], sb[idx]))
    lo, hi = np.percentile(d, [2.5, 97.5])
    return {"delta_auc": round(float(roc_auc_score(y, sa) - roc_auc_score(y, sb)), 4),
            "ci95": [round(float(lo), 4), round(float(hi), 4)]}


def mcnemar(ok_a, ok_b):
    b = int((ok_a & ~ok_b).sum())
    c = int((~ok_a & ok_b).sum())
    p = 1.0 if b + c == 0 else float(binomtest(min(b, c), b + c, 0.5).pvalue)
    return {"a_right_b_wrong": b, "a_wrong_b_right": c, "p_exact": round(p, 6)}


def corrected_t(folds_all, a, b):
    """Nadeau-Bengio corrected resampled t-test over every (repetition, fold) pair."""
    d, ratio = [], []
    for folds in folds_all:
        for f in folds:
            d.append(f["f1"][a] - f["f1"][b])
            ratio.append(f["n_test"] / f["n_train_real"])
    d = np.array(d)
    J = len(d)
    var = d.var(ddof=1)
    if var == 0:
        return {"J": J, "mean_delta": round(float(d.mean()), 4), "t": None, "p_two_sided": None}
    tt = d.mean() / np.sqrt((1.0 / J + float(np.mean(ratio))) * var)
    p = 2 * student_t.sf(abs(tt), J - 1)
    wins = int((d > 0).sum())
    return {"J": J, "mean_delta": round(float(d.mean()), 4), "sd_delta": round(float(d.std(ddof=1)), 4),
            "t": round(float(tt), 4), "df": J - 1, "p_two_sided": round(float(p), 6),
            "fold_wins_a": wins, "fold_losses_a": int((d < 0).sum())}


def holm(pvals: dict, alpha=0.05):
    order = sorted(pvals, key=pvals.get)
    out, m, still = {}, len(order), True
    for k, name in enumerate(order):
        adj = min(1.0, pvals[name] * (m - k))
        still = still and pvals[name] <= alpha / (m - k)
        out[name] = {"p": pvals[name], "holm_adjusted": round(adj, 6), "reject_h0": bool(still)}
    return out


def stage4(A, dev, allres):
    y = A["Y"][dev]
    r0 = allres[0]
    P = {m: np.array([r0["pred"][m][i] for i in dev]) for m in MODELS}
    S = {m: np.array([r0["prob"][m][i] for i in dev]) for m in MODELS}
    folds_all = [allres[r]["folds"] for r in sorted(allres)]
    res = {"rep0_metrics": {m: summary_metrics(y, P[m], S[m]) for m in MODELS}}
    rep_means = {}
    for m in MODELS:
        f1s = [f["f1"][m] for folds in folds_all for f in folds]
        rep_means[m] = {"mean_fold_f1": round(float(np.mean(f1s)), 4), "sd_fold_f1": round(float(np.std(f1s, ddof=1)), 4)
                        if len(f1s) > 1 else None}
    res["all_reps_fold_f1"] = rep_means

    ben, mal = y == 0, y == 1
    pairs = [("ML", "SP-RF"), ("CNN", "SP-RF"), ("CNN@0.5", "SP-RF"), ("ML", "SP-style"), ("CNN", "SP-style"),
             ("ML", "SP-CB"), ("CNN", "SP-CB"), ("ML", "SP-AE"), ("CNN", "SP-AE"), ("ML", "SP-RF-tuned"),
             ("CNN", "SP-RF-tuned"), ("ML", "SP-RF+synth"), ("CNN", "SP-RF+synth"), ("CNN", "ML")]
    if "CNNv2" in MODELS:
        pairs += [("CNNv2", "SP-RF"), ("CNNv2", "SP-CB"), ("CNNv2", "SP-style"),
                  ("CNNv2", "CNN"), ("CNNv2", "ML")]
    comp = {}
    for a, b in pairs:
        ok_a, ok_b = P[a] == y, P[b] == y
        comp[f"{a} vs {b}"] = {
            "bootstrap_delta_f1": boot_delta_f1(y, P[a], P[b]),
            "mcnemar_all": mcnemar(ok_a, ok_b),
            "mcnemar_benign": mcnemar(ok_a[ben], ok_b[ben]),
            "mcnemar_malicious": mcnemar(ok_a[mal], ok_b[mal]),
            "auc": boot_auc(y, S[a], S[b]),
            "corrected_t_all_reps": corrected_t(folds_all, a, b),
        }
    res["comparisons"] = comp
    primary = {
        "P1 ML vs SP-RF": comp["ML vs SP-RF"]["bootstrap_delta_f1"]["p_two_sided"],
        "P2 CNN vs SP-RF": comp["CNN vs SP-RF"]["bootstrap_delta_f1"]["p_two_sided"],
    }
    if "CNNv2" in MODELS:
        primary["P3 CNNv2 vs SP-RF"] = comp["CNNv2 vs SP-RF"]["bootstrap_delta_f1"]["p_two_sided"]
    res["primary_holm"] = holm(primary)

    # Metadata baseline: does each detector add anything over file shape? (amendment 2026-10-04)
    meta_cmp = {}
    for a in [m for m in ("ML", "CNN", "SP-RF", "SP-CB", "CNNv2") if m in MODELS]:
        ok_a, ok_m = P[a] == y, P["META"] == y
        meta_cmp[f"{a} vs META"] = {"bootstrap_delta_f1": boot_delta_f1(y, P[a], P["META"]),
                                    "mcnemar_all": mcnemar(ok_a, ok_m),
                                    "auc": boot_auc(y, S[a], S["META"])}
    res["vs_metadata_baseline"] = meta_cmp

    # Non-inferiority (section 9.1): each of our candidates against SP-RF and SP-CB, Holm over
    # the two SafePickle comparisons of that candidate.
    ni = {}
    for a in [m for m in ("ML", "CNN", "CNNv2") if m in MODELS]:
        fam = {b: boot_noninferiority(y, P[a], P[b]) for b in ("SP-RF", "SP-CB")}
        adj = holm({b: fam[b]["f1"]["p_one_sided"] for b in fam})
        for b in fam:
            fam[b]["f1"]["holm"] = adj[b]
        ni[a] = fam
    res["noninferiority"] = ni
    res["n_dev"] = int(len(y))
    res["n_reps"] = len(folds_all)
    persist("v2_dev_results.json", res)
    log("stage 4: " + json.dumps({"rep0": {m: res["rep0_metrics"][m]["f1"] for m in MODELS},
                                   "primary": res["primary_holm"]}))
    return res, P, S


# ----------------------------------------------------------------------------- stage 5
EA_VARS = ["container", "n_pkl_members", "inner_bytes", "trailing_after_stop", "n_streams", "proto",
           "n_ops_raw", "n_ops_canon", "parse_error", "first_nonallow_idx", "nonallow_beyond_window",
           "n_byte_tokens", "byte_tokens", "n_nonallowlisted", "picklescan_dangerous",
           "sem_n_members", "sem_broken", "sem_n_effects", "sem_n_calls", "sem_n_dynamic_imports",
           "sem_n_nonallow_imports", "sem_n_dead_nodes", "sem_n_emitted"]


def stage5(A, meta, dev, P, S):
    y = A["Y"][dev]
    rows = []
    for j, i in enumerate(dev):
        m = meta[i]
        r = {"path": m["path"], "sha256_16": m["sha256"][:16], "label": int(y[j])}
        r.update({k: m[k] for k in EA_VARS})
        for name in MODELS:
            r[f"pred_{name}"] = int(P[name][j])
            r[f"prob_{name}"] = round(float(S[name][j]), 5)
        rows.append(r)
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "dev_error_analysis.csv")
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    if os.path.isdir("/content/drive/MyDrive"):
        os.makedirs(DRIVE, exist_ok=True)
        with open(os.path.join(DRIVE, "dev_error_analysis.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)

    def profile(sel):
        sub = [r for r, s in zip(rows, sel) if s]
        n = len(sub)
        if n == 0:
            return {"n": 0}
        cnt = lambda f: int(sum(1 for r in sub if f(r)))
        return {
            "n": n,
            "container": {c: cnt(lambda r, c=c: r["container"] == c) for c in ("zip", "pickle", "other")},
            "payload_import_beyond_256": cnt(lambda r: r["nonallow_beyond_window"] == 1),
            "no_nonallowlisted_import": cnt(lambda r: r["n_nonallowlisted"] == 0),
            "no_byte_token": cnt(lambda r: r["n_byte_tokens"] == 0),
            "neither_import_nor_token": cnt(lambda r: r["n_nonallowlisted"] == 0 and r["n_byte_tokens"] == 0),
            "parse_error": cnt(lambda r: r["parse_error"] == 1),
            "bytes_after_first_stop": cnt(lambda r: r["trailing_after_stop"] > 0),
            "multiple_streams": cnt(lambda r: r["n_streams"] > 1),
            "zip_multiple_pkl": cnt(lambda r: r["n_pkl_members"] > 1),
            "canon_ops_gt_256": cnt(lambda r: r["n_ops_canon"] > 256),
            "picklescan_flags": cnt(lambda r: r["picklescan_dangerous"] > 0),
            "extra_pickle_members": cnt(lambda r: r["sem_n_members"] > 1),
            "semantic_emitted_gt_256": cnt(lambda r: r["sem_n_emitted"] > 256),
            "dynamic_import": cnt(lambda r: r["sem_n_dynamic_imports"] > 0),
            "has_dead_code": cnt(lambda r: r["sem_n_dead_nodes"] > 0),
        }

    mal, ben = y == 1, y == 0
    ea = {"all_malicious": profile(mal), "all_benign": profile(ben)}
    prof_names = ["CNN", "CNN@0.5", "ML", "SP-RF"] + (["CNNv2"] if "CNNv2" in MODELS else [])
    for name in prof_names:
        ea[f"FN_{name}"] = profile(mal & (P[name] == 0))
        ea[f"FP_{name}"] = profile(ben & (P[name] == 1))
    ea["FN_CNN_but_SP-RF_caught"] = profile(mal & (P["CNN"] == 0) & (P["SP-RF"] == 1))
    ea["FN_ML_but_SP-RF_caught"] = profile(mal & (P["ML"] == 0) & (P["SP-RF"] == 1))
    ea["FN_all_three"] = profile(mal & (P["CNN"] == 0) & (P["ML"] == 0) & (P["SP-RF"] == 0))
    if "CNNv2" in MODELS:
        ea["FN_CNNv2_but_SP-RF_caught"] = profile(mal & (P["CNNv2"] == 0) & (P["SP-RF"] == 1))
    persist("dev_error_profile.json", ea)
    log("stage 5: " + json.dumps({k: v.get("n") for k, v in ea.items()}))
    return ea


def restore_from_drive():
    """After a runtime recycle, copy cached features and finished repetitions back from Drive."""
    import shutil
    if not os.path.isdir(DRIVE):
        return
    os.makedirs(OUT, exist_ok=True)
    for name in os.listdir(DRIVE):
        if not os.path.exists(os.path.join(OUT, name)):
            shutil.copy2(os.path.join(DRIVE, name), os.path.join(OUT, name))
            log(f"restored {name} from Drive")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--force-features", action="store_true")
    args = ap.parse_args()
    t0 = time.time()
    restore_from_drive()
    A, meta = stage1(args.force_features)
    A["groups"] = [m["group"] for m in meta]
    if V2_OK and V2_READY:
        build_v2_arrays(A)
    dev, lock, split = stage2(A, meta)
    allres = stage3(A, dev, args.reps)
    allres = add_meta(A, meta, dev, allres)
    _res, P, S = stage4(A, dev, allres)
    stage5(A, meta, dev, P, S)
    import catboost, sklearn, torch, xgboost
    persist("run_info.json", {"minutes": round((time.time() - t0) / 60, 1), "reps": args.reps,
                              "versions": {"sklearn": sklearn.__version__, "torch": torch.__version__,
                                           "xgboost": xgboost.__version__, "catboost": catboost.__version__,
                                           "numpy": np.__version__},
                              "locked_manifest_sha256": split["locked"]["manifest_sha256"]})
    log(f"done in {(time.time() - t0) / 60:.1f} min. Download {OUT}")


if __name__ == "__main__":
    main()
