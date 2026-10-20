"""PREREGISTRATION section 14: metadata-hard subset (14.1) and three-way policy (14.2).

Reuses the saved out-of-fold predictions of the FUSE development run and the per-file metadata.
Nothing is retrained; the locked set and the PickleBall sealed half are not touched.

    python metadata_tristate_eval.py [--res results/fuse/v2] [--out results/meta_tristate]
"""
from __future__ import annotations

import argparse
import collections
import json
import os

import numpy as np

import fuse_eval as FE
import tristate as T
from fuse_eval import E, MB

MODELS = ["FUSE", "FUSE-INV", "FUSE-C", "SP-RF", "SP-CB", "META", "ML", "CNN"]
REFS = ["SP-RF", "SP-CB", "META"]
BANDS = [(0, 4096, "<=4KB"), (4096, 1 << 20, "4KB-1MB"), (1 << 20, 16 << 20, "1-16MB"), (16 << 20, None, ">16MB")]


def shortcut(m):
    return m["container"] == "pickle" and int(m["file_bytes"]) <= 4096


def band(m):
    b = int(m["file_bytes"])
    for lo, hi, name in BANDS:
        if b > lo - (lo == 0) and (hi is None or b <= hi):
            return name
    return BANDS[0][2]


def load(res):
    metas = json.load(open(os.path.join(res, "file_meta.json")))
    reps = []
    for r in range(5):
        p = os.path.join(res, f"fuse_cv_rep{r}.json")
        if os.path.exists(p):
            reps.append(json.load(open(p)))
    dev = [i for i, v in enumerate(reps[0]["pred"]["FUSE"]) if v is not None]
    return metas, reps, dev


def metrics(y, p):
    tp = int(((p == 1) & (y == 1)).sum()); fp = int(((p == 1) & (y == 0)).sum())
    fn = int(((p == 0) & (y == 1)).sum())
    f1 = 2 * tp / max(2 * tp + fp + fn, 1)
    return {"f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn,
            "recall": round(tp / max(tp + fn, 1), 4), "n_mal": int(y.sum()), "n_ben": int((y == 0).sum())}


def hard_subset(metas, reps, dev):
    H = [i for i in dev if not shortcut(metas[i])]
    y = np.array([int(metas[i]["label"]) for i in H])
    P = {m: np.array([reps[0]["pred"][m][i] for i in H]) for m in MODELS}
    out = {"n_dev": len(dev), "n_H": len(H), "n_H_malicious": int(y.sum()), "n_H_benign": int((y == 0).sum()),
           "n_shortcut_removed": len(dev) - len(H),
           "rep0": {m: metrics(y, P[m]) for m in MODELS}, "tests": {}, "reps_f1": {}}
    boots = {}
    for b in REFS:
        bd = E.boot_delta_f1(y, P["FUSE"], P[b])
        boots[b] = bd["p_two_sided"]
        out["tests"][f"FUSE vs {b}"] = {"bootstrap_delta_f1": bd,
                                        "mcnemar": E.mcnemar(P["FUSE"] == y, P[b] == y)}
    adj = FE.holm(boots)
    for b in REFS:
        out["tests"][f"FUSE vs {b}"]["holm"] = adj[b]
    for m in MODELS:
        f1s = [metrics(y, np.array([r["pred"][m][i] for i in H]))["f1"] for r in reps]
        out["reps_f1"][m] = {"mean": round(float(np.mean(f1s)), 4), "sd": round(float(np.std(f1s, ddof=1)), 4),
                             "n_reps": len(f1s)}
    beat = adj["META"]["holm_adjusted"] < 0.05 and out["tests"]["FUSE vs META"]["bootstrap_delta_f1"]["delta_f1"] > 0
    out["wording_rule"] = "survives the metadata shortcut" if beat else "comparable to META on H"
    strata = collections.defaultdict(lambda: {"n_mal": 0, "n_ben": 0, **{m: {"tp": 0, "fp": 0} for m in MODELS}})
    for i in dev:
        k = f"{metas[i]['container']}|{band(metas[i])}"
        lab = int(metas[i]["label"]); s = strata[k]
        s["n_mal" if lab else "n_ben"] += 1
        for m in MODELS:
            if reps[0]["pred"][m][i] == 1:
                s[m]["tp" if lab else "fp"] += 1
    out["strata_rep0"] = dict(sorted(strata.items()))
    return out


def three_way(metas, reps, dev):
    y = np.array([int(metas[i]["label"]) for i in dev])
    reasons = [MB.cap_reason(metas[i]) for i in dev]
    unv = np.array([r is not None for r in reasons])
    by = collections.Counter((r, int(y[j])) for j, r in enumerate(reasons) if r is not None)
    out = {"n_dev": len(dev), "unverified_benign": int((unv & (y == 0)).sum()),
           "unverified_malicious": int((unv & (y == 1)).sum()),
           "by_reason": {f"{r}|{'malicious' if l else 'benign'}": n for (r, l), n in sorted(by.items())},
           "review_load": round(float((unv & (y == 0)).sum() / max((y == 0).sum(), 1)), 4),
           "detectors": {}}
    for m in MODELS:
        p = np.array([reps[0]["pred"][m][i] for i in dev])
        v = T.verdicts(p, [metas[i] for i in dev])
        assert sum(x == T.UNVERIFIED for x in v) == int(unv.sum())
        ver = ~unv
        caught = int(((p == 1) & (y == 1) & ver).sum() + (unv & (y == 1)).sum())
        out["detectors"][m] = {
            "verified_only": metrics(y[ver], p[ver]),
            "policy": {"malicious_caught": caught, "malicious_total": int(y.sum()),
                       "recall": round(caught / max(int(y.sum()), 1), 4),
                       "recall_wilson": FE.wilson(caught, int(y.sum())),
                       "false_alarms_verified": int(((p == 1) & (y == 0) & ver).sum()),
                       "review_load_benign": int((unv & (y == 0)).sum())},
            "as_built": metrics(y, p)}
    return out


def to_md(h, t):
    L = ["# Section 14: metadata-hard subset and three-way policy (development, saved predictions)", "",
         f"## 14.1 Metadata-hard subset H ({h['n_H']} of {h['n_dev']} dev files; "
         f"{h['n_H_malicious']} malicious, {h['n_H_benign']} benign; {h['n_shortcut_removed']} bare pickles <= 4 KB removed)", "",
         "| Detector | F1 (rep 0) | Recall | FP | FN | mean F1 over reps ± SD |", "|---|---|---|---|---|---|"]
    for m in MODELS:
        r = h["rep0"][m]; s = h["reps_f1"][m]
        L.append(f"| {m} | {r['f1']} | {r['recall']} | {r['fp']} | {r['fn']} | {s['mean']} ± {s['sd']} |")
    L += ["", "| Comparison | ΔF1 [95% CI] | p (bootstrap) | Holm | McNemar (a right / b right, p) |", "|---|---|---|---|---|"]
    for k, v in h["tests"].items():
        b = v["bootstrap_delta_f1"]; mc = v["mcnemar"]
        L.append(f"| {k} | {b['delta_f1']:+.4f} [{b['ci95'][0]:+.4f}, {b['ci95'][1]:+.4f}] | {b['p_two_sided']} | "
                 f"{v['holm']['holm_adjusted']:.4f} | {mc['a_right_b_wrong']} / {mc['a_wrong_b_right']}, {mc['p_exact']} |")
    L += ["", f"Wording rule (14.1): **{h['wording_rule']}**.", "",
          "## 14.2 Three-way policy", "",
          f"UNVERIFIED: {t['unverified_benign']} benign, {t['unverified_malicious']} malicious "
          f"(review load {t['review_load']:.1%} of benign). By reason: {t['by_reason']}.", "",
          "| Detector | F1 verified only | FP verified | Policy recall [Wilson] | As built F1 |", "|---|---|---|---|---|"]
    for m in MODELS:
        d = t["detectors"][m]
        L.append(f"| {m} | {d['verified_only']['f1']} | {d['policy']['false_alarms_verified']} | "
                 f"{d['policy']['recall']} {d['policy']['recall_wilson']} | {d['as_built']['f1']} |")
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--res", default=os.path.join(FE.HERE, "results", "fuse", "v2"))
    ap.add_argument("--out", default=os.path.join(FE.HERE, "results", "meta_tristate"))
    a = ap.parse_args(argv)
    metas, reps, dev = load(a.res)
    h, t = hard_subset(metas, reps, dev), three_way(metas, reps, dev)
    os.makedirs(a.out, exist_ok=True)
    json.dump({"hard_subset": h, "three_way": t}, open(os.path.join(a.out, "meta_tristate.json"), "w"), indent=1)
    open(os.path.join(a.out, "META_TRISTATE.md"), "w").write(to_md(h, t))
    print(to_md(h, t))


if __name__ == "__main__":
    main()
