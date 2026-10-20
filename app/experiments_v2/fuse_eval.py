"""FUSE: the pre-registered fused static detector (PREREGISTRATION section 11, fixed 2026-10-05).

Why it exists. On the de-duplicated development set no single learned detector beats a faithful
SafePickle, and a metadata-only logistic regression (META) is numerically first. SafePickle is never
evaded in the real-file attack study but scores F1 0 on non-pickle containers, where META and our
detectors recover. FUSE puts the signals that each win somewhere into one model, and FUSE-INV keeps
only the features that the semantic canonical form makes invariant to inert insertion (PROOFS.md
Theorem 1), so that its robustness to the insertion families follows from the construction.

Detectors (all trained on REAL training-fold files only, threshold 0.5 fixed, no tuning):
  FUSE      SafePickle opcode frequency + semantic canonical opcode frequency + all semantic stats
            (log1p) + META metadata vector + v1 scalars.
  FUSE-C    content only: SafePickle frequency + semantic frequency + all semantic stats.
            Reported to measure how much of FUSE is the metadata shortcut.
  FUSE-INV  semantic canonical opcode frequency + the stats read from the canonical graph's live
            part only (INV_KEYS). Every feature is a function of the canonical form, so by Theorem 1
            the score does not change under an inert insertion that stays within the read caps.
Model of every detector: mean of RandomForest(500 trees) and HistGradientBoosting, seed = repetition.
Each is also reported "+FC" (fail-closed: unverified streams flagged, meta_baseline.fail_closed).

Modes (nothing is ever deserialised, every feature is computed statically by encode_file):
  python fuse_eval.py                         dev 5x5 grouped CV on the stage-1 feature cache,
                                              same folds as colab_v2_eval.stage3; SP-RF, SP-CB and
                                              META are re-fitted on the identical folds so every
                                              comparison is paired. Writes fuse_dev_results.json.
  python fuse_eval.py --attack --seed S       out-of-fold attack study (attack_study_real harness,
                                              existing families only) with the FUSE rows added.
                                              Writes attack_study_fuse_seed<S>.json.
  python fuse_eval.py --final-run --confirm-single-final-run
                                              THE single locked-test run of PREREGISTRATION section 6:
                                              every frozen detector (colab_v2_eval.run_fold on the whole
                                              dev set) plus META and FUSE*, scored once on the locked 139.
                                              Refuses to run twice (marker file). Do NOT run it before
                                              the adoption decision is written into the amendment log.
  python fuse_eval.py --self-test             laptop dry-run on harmless synthetic pickles.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import time

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedGroupKFold

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
for p in (APP, HERE, os.path.join(HERE, "ned2")):
    if p not in sys.path:
        sys.path.insert(0, p)

import colab_v2_eval as E                                   # noqa: E402
import meta_baseline as MB                                  # noqa: E402

OUT = E.OUT
DETS = ("FUSE", "FUSE-C", "FUSE-INV")
BASES = ("SP-RF", "SP-CB", "META")
SEM_KEYS = E.SEM_KEYS
# Stats computed on the live (reachable) part of the canonical graph or on the archive layout.
# Excluded because an inert insertion can change them: broken, n_streams, n_ops_raw (raw stream),
# n_dynamic_imports and n_persid (count dead nodes too), n_dead_nodes, dead_fraction.
INV_KEYS = ("n_members", "n_effects", "n_calls", "n_static_imports", "n_nonallow_imports", "n_emitted")
_INV_IDX = [SEM_KEYS.index(k) for k in INV_KEYS]
FINAL_MARKER = "FINAL_RUN_DONE.json"
STARTED_MARKER = "FINAL_RUN_STARTED.json"     # written before any training; blocks every later attempt
CRASH_MARKER = "FINAL_RUN_CRASHED.json"
DRIVE_ROOT = "/content/drive/MyDrive"
# The pre-registered final run happened (results/final/). Markers live on Drive, which differs between
# Colab accounts, so the code itself now refuses a further locked-test run (FAILURE_LOG F-96).
FINAL_RUN_EXECUTED_AT = "2026-10-05 09:47 UTC (repeated by mistake at 12:18 UTC)"
# PREREGISTRATION section 6: the locked split the final run must score (same constant as cap_audit.py).
EXPECTED_LOCKED_MANIFEST = "1aaa27a48abab0a0ca30b26a1ba829b43c0376d67580e865c19227b3c394c142"


def log(msg):
    E.log(f"[fuse] {msg}")


# ----------------------------------------------------------------------------- features
def sem_freq_one(tokens) -> np.ndarray:
    """Normalised histogram of the semantic canonical stream (tokens are OPCODE_INDEX + 1)."""
    h = np.zeros(E.N_OPS, np.float32)
    t = np.asarray(tokens, dtype=np.int64)
    t = t[(t >= 1) & (t <= E.N_OPS)]
    if t.size:
        np.add.at(h, t - 1, 1.0)
        h /= h.sum()
    return h


def sem_freq_matrix(sem_seq, sem_off) -> np.ndarray:
    return np.stack([sem_freq_one(sem_seq[sem_off[i]:sem_off[i + 1]]) for i in range(len(sem_off) - 1)])


def feature_matrix(kind, R, SF, ST, M, C):
    """R raw opcode counts, SF semantic freq, ST semantic stats, M meta vectors, C v1 scalars."""
    st = np.log1p(np.maximum(np.asarray(ST, dtype=np.float64), 0.0))
    if kind == "FUSE":
        parts = [E.freq(np.asarray(R, np.float32)), SF, st, np.asarray(M, np.float64), np.asarray(C)]
    elif kind == "FUSE-C":
        parts = [E.freq(np.asarray(R, np.float32)), SF, st]
    elif kind == "FUSE-INV":
        parts = [SF, st[:, _INV_IDX]]
    else:
        raise ValueError(kind)
    return np.hstack([np.asarray(p, np.float64) for p in parts])


class Cache:
    """Per-file feature blocks of the real corpus, from the stage-1 cache (no file is re-read)."""

    def __init__(self, A, metas):
        self.R, self.C, self.ST = A["R"], A["C"], A["sem_stats"]
        self.SF = sem_freq_matrix(A["sem_seq"], A["sem_off"])
        self.M = np.array([MB.meta_vec(m) for m in metas], dtype=float)

    def X(self, kind, idx):
        idx = np.asarray(idx)
        return feature_matrix(kind, self.R[idx], self.SF[idx], self.ST[idx], self.M[idx], self.C[idx])


def X_from_encs(kind, encs):
    """The same features for freshly encoded buffers (attack variants, final run)."""
    return feature_matrix(kind,
                          np.vstack([e["counts"] for e in encs]),
                          np.stack([sem_freq_one(e["sem_seq"]) for e in encs]),
                          np.stack([e["sem_stats"] for e in encs]),
                          np.array([MB.meta_vec(e["meta"]) for e in encs], dtype=float),
                          np.stack([e["sc"] for e in encs]))


def fit_fuse(Xtr, ytr, seed):
    """Mean of a 500-tree RandomForest and a HistGradientBoosting model. Fixed, untuned."""
    rf = RandomForestClassifier(n_estimators=500, random_state=int(seed), n_jobs=-1).fit(Xtr, ytr)
    gb = HistGradientBoostingClassifier(random_state=int(seed)).fit(Xtr, ytr)
    return lambda X: 0.5 * (rf.predict_proba(X)[:, 1] + gb.predict_proba(X)[:, 1])


def holm(pvals: dict, alpha=0.05):
    """colab_v2_eval.holm with monotone adjusted p-values (running maximum in the step-down
    order). The reject decisions are E.holm's, unchanged; only holm_adjusted is corrected."""
    out = E.holm(pvals, alpha)
    running = 0.0
    for name in sorted(pvals, key=pvals.get):              # the order E.holm uses
        running = max(running, out[name]["holm_adjusted"])
        out[name]["holm_adjusted"] = running
    return out


def wilson(k, n, z=1.959964):
    """Wilson score 95 % interval for k successes out of n."""
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


# ----------------------------------------------------------------------------- dev CV
def dev_cv(A, metas, dev, reps=5):
    y, groups = np.asarray(A["Y"]), np.array([m["group"] for m in metas])
    cache = Cache(A, metas)
    Fr = E.freq(np.asarray(A["R"], np.float32))
    models = DETS + BASES
    allres = {}
    for rep in range(reps):
        prob = {m: [None] * len(y) for m in models}
        pred = {m: [None] * len(y) for m in models}
        folds = []
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=rep)
        for k, (trp, tep) in enumerate(sgkf.split(np.zeros(len(dev)), y[dev], groups[dev])):
            tr, te = dev[trp], dev[tep]
            t0 = time.time()
            out = {}
            for d in DETS:
                out[d] = fit_fuse(cache.X(d, tr), y[tr], rep)(cache.X(d, te))
            out["SP-RF"] = E.fit_sp_rf(Fr[tr], y[tr], rep)(Fr[te])
            try:
                out["SP-CB"] = E.fit_sp_cb(Fr[tr], y[tr], rep)(Fr[te])
            except Exception as exc:                        # noqa: BLE001  catboost missing
                log(f"SP-CB skipped: {exc}")
                out.pop("SP-CB", None)
            out["META"] = MB.fit_meta([metas[i] for i in tr], y[tr], rep)([metas[i] for i in te])
            fold = {"fold": k, "n_train_real": int(len(tr)), "n_test": int(len(te)),
                    "seconds": round(time.time() - t0, 1), "f1": {}}
            for m, p in out.items():
                d = (np.asarray(p) >= 0.5).astype(int)
                for j, i in enumerate(te):
                    prob[m][i], pred[m][i] = float(p[j]), int(d[j])
                fold["f1"][m] = round(float(f1_score(y[te], d, zero_division=0)), 4)
            folds.append(fold)
            log(f"rep {rep} fold {k + 1}/5 {fold['seconds']}s " +
                " ".join(f"{m}={fold['f1'][m]:.3f}" for m in models if m in fold["f1"]))
        allres[rep] = {"folds": folds, "prob": prob, "pred": pred}
    return allres


def attach_saved(allres, dev):
    """Add ML / CNN / CNN@0.5 from the saved cv_rep*.json of the main run when its folds match."""
    added = {}
    for rep, r in allres.items():
        ck = os.path.join(OUT, f"cv_rep{rep}.json")
        if not os.path.exists(ck):
            continue
        saved = json.load(open(ck, encoding="utf-8"))
        if [f["n_test"] for f in saved["folds"]] != [f["n_test"] for f in r["folds"]]:
            log(f"cv_rep{rep}.json has different folds; saved detectors not attached")
            continue
        sp_saved = [saved["pred"]["SP-RF"][i] for i in dev]
        sp_here = [r["pred"]["SP-RF"][i] for i in dev]
        added[rep] = {"sp_rf_agreement_with_saved": round(float(np.mean(np.array(sp_saved) == np.array(sp_here))), 4)}
        for m in ("ML", "CNN", "CNN@0.5"):
            if m in saved["pred"] and all(saved["pred"][m][i] is not None for i in dev):
                r["prob"][m], r["pred"][m] = saved["prob"][m], saved["pred"][m]
                for fs, fh in zip(saved["folds"], r["folds"]):
                    fh["f1"][m] = fs["f1"][m]
    return added


def dev_stats(A, metas, dev, allres):
    y = np.asarray(A["Y"])[dev]
    r0 = allres[0]
    models = [m for m in r0["pred"] if all(r0["pred"][m][i] is not None for i in dev)]
    P = {m: np.array([r0["pred"][m][i] for i in dev]) for m in models}
    S = {m: np.array([r0["prob"][m][i] for i in dev]) for m in models}
    mdev = [metas[i] for i in dev]
    folds_all = [allres[r]["folds"] for r in sorted(allres)]
    res = {"n_dev": int(len(y)), "n_reps": len(folds_all),
           "rep0_metrics": {m: E.summary_metrics(y, P[m], S[m]) for m in models},
           "rep0_metrics_fail_closed": {m: E.summary_metrics(y, MB.fail_closed(P[m], mdev), S[m]) for m in models},
           "all_reps_fold_f1": {}}
    for m in models:
        f1s = [f["f1"][m] for fs in folds_all for f in fs if m in f["f1"]]
        res["all_reps_fold_f1"][m] = {"mean_fold_f1": round(float(np.mean(f1s)), 4),
                                      "sd_fold_f1": round(float(np.std(f1s, ddof=1)), 4), "n_folds": len(f1s)}
    comp, ni, sup = {}, {}, {}
    refs = [b for b in ("SP-RF", "SP-CB", "META", "CNN", "ML") if b in models]
    for a in DETS:
        for b in refs:
            ok_a, ok_b = P[a] == y, P[b] == y
            comp[f"{a} vs {b}"] = {"bootstrap_delta_f1": E.boot_delta_f1(y, P[a], P[b]),
                                   "mcnemar_all": E.mcnemar(ok_a, ok_b),
                                   "auc": E.boot_auc(y, S[a], S[b]),
                                   "corrected_t_all_reps": E.corrected_t(
                                       [[f for f in fs if a in f["f1"] and b in f["f1"]] for fs in folds_all], a, b)}
        fam = {b: E.boot_noninferiority(y, P[a], P[b]) for b in ("SP-RF", "SP-CB") if b in models}
        adj = holm({b: fam[b]["f1"]["p_one_sided"] for b in fam})
        for b in fam:
            fam[b]["f1"]["holm"] = adj[b]
        ni[a] = fam
        sup[f"{a} vs SP-RF"] = comp[f"{a} vs SP-RF"]["bootstrap_delta_f1"]["p_two_sided"]
    res["comparisons"], res["noninferiority"] = comp, ni
    res["superiority_vs_sp_rf_holm"] = holm(sup)
    by = {}
    for c in ("pickle", "zip", "other"):
        idx = np.array([j for j, m in enumerate(mdev) if m["container"] == c])
        if idx.size:
            by[c] = {"n": int(idx.size), "n_malicious": int(y[idx].sum()),
                     **{m: {"tp": int(((P[m][idx] == 1) & (y[idx] == 1)).sum()),
                            "fp": int(((P[m][idx] == 1) & (y[idx] == 0)).sum())} for m in models}}
    res["by_container_rep0"] = by
    return res


# ----------------------------------------------------------------------------- attack study
def encode_with_sem(buf):
    vec, seq, sc, counts, _full, meta, sem_seq, sem_stats = E.encode_file(buf)
    return {"vec": vec, "seq": seq, "sc": sc, "counts": counts, "meta": meta,
            "sem_seq": sem_seq, "sem_stats": sem_stats}


def make_fuse_trainer(A, metas, seed=0, cheap=True, use_cnn=False):
    import attack_study_real as AS
    base = AS.make_trainer(A, metas, seed=seed, cheap=cheap, use_cnn=use_cnn)
    cache = Cache(A, metas)
    y = np.asarray(A["Y"])

    def train(tr):
        tr = np.asarray(tr)
        dets = base(tr)
        for d in DETS:
            model = fit_fuse(cache.X(d, tr), y[tr], seed)
            dets[d] = ((lambda encs, _m=model, _d=d: _m(X_from_encs(_d, encs))), {d: 0.5})
        return dets
    return train


def source_sha256():
    with open(os.path.abspath(__file__), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def run_attack(A, metas, dev, *, seed, n_mal, folds, with_cnn, ckpt_dir, data_root):
    import attack_study_real as AS
    from collections import Counter
    y = np.asarray(A["Y"])
    groups = np.array([m["group"] for m in metas])
    origins = {int(i): AS.origin_of(metas[i]["path"]) for i in dev}
    sampled = AS.sample_malicious([int(i) for i in dev if y[i] == 1], origins, n_mal, seed)

    def load_bytes(i):
        with open(os.path.join(data_root, metas[i]["path"]), "rb") as fh:
            return fh.read()

    def info(i):
        return {"origin": origins[i], "path": metas[i]["path"], "sha256": metas[i]["sha256"],
                "container": metas[i]["container"]}

    fp = AS.run_fingerprint(n_mal, seed, folds, True, [metas[i]["sha256"] for i in sampled], cnn=with_cnn)
    fp["fuse_source_sha256"] = source_sha256()
    records, fold_info, rows = AS.evaluate_oof(
        dev, y, groups, sampled, load_bytes, make_fuse_trainer(A, metas, seed=seed, use_cnn=with_cnn),
        k=folds, seed=seed, encode_fn=encode_with_sem, info=info, ckpt_dir=ckpt_dir, fingerprint=fp)
    config = {"n_mal": n_mal, "seed": seed, "folds": folds, "cnn": with_cnn, "n_dev": int(len(dev)),
              "sampled_by_origin": dict(Counter(origins[i] for i in sampled))}
    res = AS.build_report(records, fold_info, rows, config)
    print(AS.format_tables(res["summary"], rows))
    return res


# ----------------------------------------------------------------------------- final run
def final_run(A, metas, dev, lock, split, expected_manifest=EXPECTED_LOCKED_MANIFEST, allow_repeat=False):
    """Single locked-test run (PREREGISTRATION section 6 and 11). Refuses to run twice, and refuses
    to score any split other than the pre-registered one (checked before anything is trained)."""
    if FINAL_RUN_EXECUTED_AT and not allow_repeat:
        raise SystemExit(f"the locked test was already scored ({FINAL_RUN_EXECUTED_AT}); see results/final/. "
                         "It is not scored again (FAILURE_LOG F-96).")
    for d in (OUT, E.DRIVE):
        for name in (FINAL_MARKER, STARTED_MARKER):
            mk = os.path.join(d, name)
            if os.path.exists(mk):
                raise SystemExit(f"final run already started or done ({mk}); it is executed once only. "
                                 "If it crashed, read FINAL_RUN_CRASHED.json and decide with the author.")
    got = split["locked"]["manifest_sha256"]
    if expected_manifest is not None and got != expected_manifest:
        raise SystemExit(f"locked manifest {got[:12]} is not the pre-registered {expected_manifest[:12]}; "
                         "the final run scores only the pre-registered locked split.")
    E.persist(STARTED_MARKER, {"started": time.strftime("%Y-%m-%d %H:%M:%S"), "manifest": got,
                               "source_sha256": source_sha256()})
    try:
        return _final_run_body(A, metas, dev, lock, split)
    except BaseException as exc:
        import traceback
        E.persist(CRASH_MARKER, {"time": time.strftime("%Y-%m-%d %H:%M:%S"),
                                 "error": f"{type(exc).__name__}: {exc}"[:500],
                                 "traceback": traceback.format_exc()[-4000:]})
        raise


def _final_run_body(A, metas, dev, lock, split):
    y = np.asarray(A["Y"])
    log(f"FINAL RUN: training every detector on dev ({len(dev)}) and scoring locked ({len(lock)}) once")
    res_all, _sec = E.run_fold(A, dev, lock, seed=0)
    P = {m: np.asarray(d) for m, (_p, d, _t) in res_all.items()}
    S = {m: np.asarray(p) for m, (p, _d, _t) in res_all.items()}
    S["META"] = MB.fit_meta([metas[i] for i in dev], y[dev], 0)([metas[i] for i in lock])
    P["META"] = (S["META"] >= 0.5).astype(int)
    cache = Cache(A, metas)
    for d in DETS:
        S[d] = fit_fuse(cache.X(d, dev), y[dev], 0)(cache.X(d, lock))
        P[d] = (S[d] >= 0.5).astype(int)
    yl, ml = y[lock], [metas[i] for i in lock]
    out = {"locked_manifest_sha256": split["locked"]["manifest_sha256"], "n_locked": int(len(lock)),
           "metrics": {m: E.summary_metrics(yl, P[m], S[m]) for m in P},
           "metrics_fail_closed": {m: E.summary_metrics(yl, MB.fail_closed(P[m], ml), S[m]) for m in P},
           "noninferiority": {}, "superiority": {}, "per_file": {}}
    for a in [m for m in ("FUSE", "FUSE-INV", "FUSE-C", "ML", "CNN", "CNNv2") if m in P]:
        fam = {b: E.boot_noninferiority(yl, P[a], P[b]) for b in ("SP-RF", "SP-CB") if b in P}
        adj = holm({b: fam[b]["f1"]["p_one_sided"] for b in fam})
        for b in fam:
            fam[b]["f1"]["holm"] = adj[b]
        out["noninferiority"][a] = fam
        out["superiority"][a] = {b: E.boot_delta_f1(yl, P[a], P[b]) for b in ("SP-RF", "SP-CB", "META") if b in P}
    out["per_file"] = {metas[i]["sha256"]: {"label": int(y[i]), **{m: int(P[m][j]) for m in P}}
                       for j, i in enumerate(lock)}
    npos, nneg = int((yl == 1).sum()), int((yl == 0).sum())
    out["wilson95"] = {m: {"recall": wilson(int(((P[m] == 1) & (yl == 1)).sum()), npos),
                           "false_alarm_rate": wilson(int(((P[m] == 1) & (yl == 0)).sum()), nneg)} for m in P}
    out["mcnemar_fuse"] = {b: E.mcnemar(P["FUSE"] == yl, P[b] == yl) for b in ("SP-RF", "SP-CB", "META") if b in P}
    E.persist("final_locked_results.json", out)
    for d in [OUT] + ([E.DRIVE] if os.path.isdir(DRIVE_ROOT) else []):
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "final_locked_results.md"), "w", encoding="utf-8") as fh:
            fh.write(final_md(out))
    stamp = {"done": True, "manifest": out["locked_manifest_sha256"], "time": time.strftime("%Y-%m-%d %H:%M:%S")}
    E.persist(FINAL_MARKER, stamp)
    log("FINAL RUN written: final_locked_results.json (" +
        " ".join(f"{m}={out['metrics'][m]['f1']}" for m in out["metrics"]) + ")")
    return out


def final_md(out):
    """Markdown summary of final_locked_results.json (formatting only)."""
    L = ["# Final run: locked test (scored once)", "",
         f"Locked manifest `{out['locked_manifest_sha256'][:12]}…`, {out['n_locked']} files.", "",
         "| Detector | F1 | Precision | Recall [Wilson 95%] | FA rate [Wilson 95%] | AUC | F1 +FC |",
         "|---|---|---|---|---|---|---|"]
    for m, v in out["metrics"].items():
        w = out["wilson95"][m]
        fa = v["FP"] / max(v["FP"] + v["TN"], 1)
        L.append(f"| {m} | {v['f1']} | {v['precision']} | {v['recall']} {w['recall']} | {fa:.4f} "
                 f"{w['false_alarm_rate']} | {v['auc']} | {out['metrics_fail_closed'][m]['f1']} |")
    L += ["", "Non-inferiority (margin −0.02 F1, Holm over SP-RF / SP-CB):"]
    for a, fam in out["noninferiority"].items():
        L.append(f"- {a}: " + "; ".join(f"vs {b} lower bound {v['f1'].get('lower_bound_95_one_sided')}, "
                                         f"Holm p {v['f1'].get('holm', {}).get('holm_adjusted')}, "
                                         f"{'non-inferior' if v['f1'].get('holm', {}).get('reject_h0') else 'not shown'}"
                                         for b, v in fam.items()))
    if "FUSE" in out["superiority"]:
        L += ["", "FUSE against the baselines (paired bootstrap ΔF1, McNemar):"]
        for b, v in out["superiority"]["FUSE"].items():
            mc = out["mcnemar_fuse"].get(b, {})
            L.append(f"- vs {b}: ΔF1 {v.get('delta_f1')} {v.get('ci95')}, p {v.get('p_two_sided')}; McNemar "
                     f"{mc.get('a_right_b_wrong')} vs {mc.get('a_wrong_b_right')}, p {mc.get('p_exact')}")
    return "\n".join(L) + "\n"


# ----------------------------------------------------------------------------- self-test
def _self_test():
    import attack_study_real as AS
    bufs, y, origins, synth, ys = AS._synthetic_corpus()
    encs = [encode_with_sem(b) for b in bufs]
    metas = [dict(e["meta"], path=f"{o}/{i}", label=int(lab)) for i, (e, o, lab) in enumerate(zip(encs, origins, y))]
    A = AS._arrays(encs)
    A["Y"] = y
    A["sem_stats"] = np.stack([e["sem_stats"] for e in encs])
    A["sem_seq"] = np.concatenate([e["sem_seq"] for e in encs])
    A["sem_off"] = np.cumsum([0] + [len(e["sem_seq"]) for e in encs]).astype(np.int64)
    sA = AS._arrays([encode_with_sem(b) for b in synth])
    A.update({"XS": sA["X"], "SS": sA["S"], "CS": sA["C"], "YS": ys})
    # invariance check: FUSE-INV features are equal for a file and for its kept inert variants
    import random
    from picklecore import attacks
    n_checked = n_equal = 0
    for i in [k for k in range(len(bufs)) if y[k] == 1][:6]:
        x0 = X_from_encs("FUSE-INV", [encs[i]])
        for vname, vb in attacks.attack_variants(bufs[i], random.Random(i)):
            if not vname.startswith("A1") or not attacks.still_carries_payload(bufs[i], vb):
                continue
            n_checked += 1
            n_equal += int(np.allclose(x0, X_from_encs("FUSE-INV", [encode_with_sem(vb)])))
    log(f"self-test: FUSE-INV features unchanged on {n_equal}/{n_checked} A1/A1b variants")
    dev = np.arange(len(bufs))
    allres = dev_cv(A, metas, dev, reps=1)
    st = dev_stats(A, metas, dev, allres)
    log("self-test dev CV ok: " + json.dumps({m: v["f1"] for m, v in st["rep0_metrics"].items()}))
    res = AS.evaluate_oof(dev, y, np.array([m["group"] for m in metas]),
                          AS.sample_malicious([i for i in dev if y[i] == 1], {i: origins[i] for i in dev}, 8, 0),
                          lambda i: bufs[i], make_fuse_trainer(A, metas, seed=0, use_cnn=False),
                          k=3, seed=0, encode_fn=encode_with_sem,
                          info=lambda i: {"origin": origins[i], "sha256": metas[i]["sha256"]})
    rows = res[2]
    assert all(d in rows for d in DETS), rows
    log(f"self-test attack harness ok, rows {rows}")
    return n_equal, n_checked


# ----------------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--attack", action="store_true")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n-mal", type=int, default=40)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--with-cnn", action="store_true", help="also train the v1 CNN in the attack study")
    ap.add_argument("--ckpt-dir", default=None)
    ap.add_argument("--final-run", action="store_true")
    ap.add_argument("--confirm-single-final-run", action="store_true")
    ap.add_argument("--allow-no-drive", action="store_true",
                    help="run the final run in Colab without Drive (its once-only markers then live only locally)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        _self_test()
        return
    t0 = time.time()
    E.restore_from_drive()
    log(f"fuse_eval source {source_sha256()[:12]}")
    if not os.path.exists(os.path.join(OUT, "features_cache.npz")) and not os.path.isdir(E.DATA):
        log("no features_cache.npz in OUT or on Drive and no corpus under E.DATA: stage 1 will need the corpus "
            "(run COLAB_RUN_ALL first, or download it with v2_download.py)")
    A, metas = E.stage1()
    A["groups"] = [m["group"] for m in metas]
    dev, lock, split = E.stage2(A, metas)
    if args.final_run:
        if not args.confirm_single_final_run:
            raise SystemExit("--final-run needs --confirm-single-final-run (the locked set is scored once only)")
        if os.path.isdir("/content") and not os.path.isdir(DRIVE_ROOT) and not args.allow_no_drive:
            raise SystemExit("Colab without Drive: the once-only markers would be lost with the runtime. "
                             "Mount Drive (cell 1) or pass --allow-no-drive.")
        if E.V2_OK and not E.V2_READY:
            log("note: CNNv2 is not enabled in colab_v2_eval (V2_READY False); it is not in the final run")
        final_run(A, metas, dev, lock, split)
    elif args.attack:
        res = run_attack(A, metas, dev, seed=args.seed, n_mal=args.n_mal, folds=args.folds,
                         with_cnn=args.with_cnn, ckpt_dir=args.ckpt_dir, data_root=E.DATA)
        res["minutes"] = round((time.time() - t0) / 60, 1)
        E.persist(f"attack_study_fuse_seed{args.seed}.json", res)
    else:
        allres = dev_cv(A, metas, dev, reps=args.reps)
        saved = attach_saved(allres, dev)
        res = dev_stats(A, metas, dev, allres)
        res["saved_detectors_attached"] = saved
        res["source_sha256"] = source_sha256()
        res["minutes"] = round((time.time() - t0) / 60, 1)
        E.persist("fuse_dev_results.json", res)
        for rep, r in allres.items():
            E.persist(f"fuse_cv_rep{rep}.json", r)
        print(json.dumps({"rep0_f1": {m: v["f1"] for m, v in res["rep0_metrics"].items()},
                          "mean_fold_f1": {m: v["mean_fold_f1"] for m, v in res["all_reps_fold_f1"].items()},
                          "noninferiority": {a: {b: v["f1"]["non_inferior"] for b, v in fam.items()}
                                             for a, fam in res["noninferiority"].items()},
                          "superiority_vs_sp_rf_holm": res["superiority_vs_sp_rf_holm"]}, indent=1))
    log(f"done in {(time.time() - t0) / 60:.1f} min")


if __name__ == "__main__":
    main()
