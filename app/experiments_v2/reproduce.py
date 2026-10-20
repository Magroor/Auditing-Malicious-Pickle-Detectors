"""Recompute the paper's real-corpus tables and tests from the released per-file predictions.

    python reproduce.py --experiment dev           # Table III top: development 5x5 CV, repetition 0
    python reproduce.py --experiment locked_test   # Table III middle: the single locked-test run
    python reproduce.py --experiment section14     # metadata-hard subset and three-way verdict
    python reproduce.py --experiment all

Nothing is trained or scored: every number is recomputed from saved out-of-fold and locked-test
predictions (results/fuse/v2, results/final), with the same bootstrap, Holm, McNemar and Wilson code
the runs used. The locked set is never re-scored (PREREGISTRATION section 6, FAILURE_LOG F-96).
"""
from __future__ import annotations

import argparse
import json
import os

import numpy as np

import fuse_eval as FE
from fuse_eval import E

RES = os.path.join(FE.HERE, "results")
DEV_MODELS = ["FUSE", "FUSE-INV", "FUSE-C", "SP-RF", "SP-CB", "META", "ML", "CNN"]
LOCK_MODELS = ["FUSE", "FUSE-INV", "FUSE-C", "SP-RF", "SP-CB", "META", "ML", "CNN"]


def ni_holm(y, P, a, refs=("SP-RF", "SP-CB")):
    fam = {b: E.boot_noninferiority(y, P[a], P[b]) for b in refs}
    adj = FE.holm({b: fam[b]["f1"]["p_one_sided"] for b in fam})
    return {b: {"lower_bound": fam[b]["f1"]["lower_bound_95_one_sided"], "holm_p": adj[b]["holm_adjusted"],
                "non_inferior": bool(fam[b]["f1"]["lower_bound_95_one_sided"] > -0.02 and adj[b]["reject_h0"])}
            for b in fam}


def dev(res=os.path.join(RES, "fuse", "v2")):
    metas = json.load(open(os.path.join(res, "file_meta.json")))
    r0 = json.load(open(os.path.join(res, "fuse_cv_rep0.json")))
    idx = [i for i, v in enumerate(r0["pred"]["FUSE"]) if v is not None]
    y = np.array([int(metas[i]["label"]) for i in idx])
    P = {m: np.array([r0["pred"][m][i] for i in idx]) for m in DEV_MODELS}
    out = {"n": len(idx), "metrics": {m: E.summary_metrics(y, P[m], P[m].astype(float)) for m in DEV_MODELS},
           "fuse_vs": {b: E.boot_delta_f1(y, P["FUSE"], P[b]) for b in ("SP-RF", "SP-CB", "META")},
           "noninferiority": {a: ni_holm(y, P, a) for a in ("FUSE", "FUSE-INV", "FUSE-C")}}
    return out


def locked_test(path=os.path.join(RES, "final", "final_locked_results.json")):
    d = json.load(open(path))
    rows = list(d["per_file"].values())                    # order = the run's locked index order
    y = np.array([r["label"] for r in rows])
    P = {m: np.array([r[m] for r in rows]) for m in LOCK_MODELS}
    npos, nneg = int(y.sum()), int((y == 0).sum())
    out = {"n": len(rows), "manifest": d["locked_manifest_sha256"],
           "metrics": {m: E.summary_metrics(y, P[m], P[m].astype(float)) for m in LOCK_MODELS},
           "wilson95": {m: {"recall": FE.wilson(int(((P[m] == 1) & (y == 1)).sum()), npos),
                            "false_alarms": FE.wilson(int(((P[m] == 1) & (y == 0)).sum()), nneg)} for m in LOCK_MODELS},
           "noninferiority": {a: ni_holm(y, P, a) for a in ("FUSE", "FUSE-INV", "FUSE-C", "ML", "CNN")},
           "mcnemar_fuse": {b: E.mcnemar(P["FUSE"] == y, P[b] == y) for b in ("SP-RF", "SP-CB", "META")}}
    return out


def section14():
    import metadata_tristate_eval as M
    metas, reps, idx = M.load(os.path.join(RES, "fuse", "v2"))
    return {"hard_subset": M.hard_subset(metas, reps, idx), "three_way": M.three_way(metas, reps, idx)}


def to_md(name, r):
    if name == "section14":
        import metadata_tristate_eval as M
        return M.to_md(r["hard_subset"], r["three_way"])
    L = [f"## {name} ({r['n']} files)", "", "| Detector | TP | FP | FN | F1 |", "|---|---|---|---|---|"]
    for m, v in r["metrics"].items():
        L.append(f"| {m} | {v['TP']} | {v['FP']} | {v['FN']} | {v['f1']} |")
    L += ["", "Non-inferiority (margin −0.02, Holm over SP-RF/SP-CB):"]
    for a, fam in r["noninferiority"].items():
        L.append(f"- {a}: " + "; ".join(f"vs {b} lower bound {v['lower_bound']}, Holm p {v['holm_p']:.4f}, "
                                        f"{'holds' if v['non_inferior'] else 'fails'}" for b, v in fam.items()))
    if "fuse_vs" in r:
        L += [""] + [f"- FUSE − {b}: ΔF1 {v['delta_f1']:+.4f} {v['ci95']}, p {v['p_two_sided']}" for b, v in r["fuse_vs"].items()]
    if "mcnemar_fuse" in r:
        L += [""] + [f"- McNemar FUSE vs {b}: {v}" for b, v in r["mcnemar_fuse"].items()]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--experiment", choices=["dev", "locked_test", "section14", "all"], default="all")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    a = ap.parse_args(argv)
    names = ["dev", "locked_test", "section14"] if a.experiment == "all" else [a.experiment]
    fns = {"dev": dev, "locked_test": locked_test, "section14": section14}
    for n in names:
        r = fns[n]()
        print(json.dumps(r, indent=1, default=str) if a.json else to_md(n, r))


if __name__ == "__main__":
    main()
