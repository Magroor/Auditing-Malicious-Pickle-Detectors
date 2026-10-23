"""Threshold sweep and score distributions on the 166 official checkpoints (exploratory).

Input: external_official_scores.json from COLAB_OFFICIAL_SCORES.ipynb (raw scores per detector and file).
Optional: the first development run's out-of-fold scores, to show the recall a threshold costs.

For each detector it reports:
  * the distribution of scores on the official (benign) checkpoints, all files and verified files only;
  * the false-alarm rate with a Wilson 95 percent interval at a grid of thresholds;
  * the threshold that keeps at most 0, 1, 5 and 10 percent of the verified checkpoints flagged, and the
    development recall at that threshold (out-of-fold, first run; indicative only, because the external
    scores come from models trained on all 886 files and the development scores from fold models);
  * an indicative cross-source ROC AUC: official checkpoints as negatives, development malicious files
    (out-of-fold) as positives.

Usage (from the project root):
  python app/experiments_v2/official_threshold_sweep.py --scores path/to/external_official_scores.json
      [--dev-dir app/experiments_v2/results/fuse/v2] [--out-dir app/experiments_v2/results/official_scores]
      [--fig paper_v3/figs/fig_external_scores.pdf]
"""
import argparse
import json
import math
import os

import numpy as np

DETECTORS = ("FUSE", "FUSE-INV", "SP-RF", "SP-CB", "META", "ML", "CNN")
TARGETS = (0.0, 0.01, 0.05, 0.10)


def wilson(k, n, z=1.959964):
    if n == 0:
        return [None, None]
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return [round((c - h) / d, 4), round((c + h) / d, 4)]


def auc(neg, pos):
    """Mann-Whitney AUC with ties counted as one half."""
    neg, pos = np.asarray(neg, float), np.asarray(pos, float)
    if not len(neg) or not len(pos):
        return None
    allv = np.concatenate([neg, pos])
    order = allv.argsort(kind="mergesort")
    ranks = np.empty(len(allv))
    sv = allv[order]
    i = 0
    while i < len(sv):
        j = i
        while j + 1 < len(sv) and sv[j + 1] == sv[i]:
            j += 1
        ranks[order[i:j + 1]] = (i + j) / 2 + 1
        i = j + 1
    rp = ranks[len(neg):].sum()
    return round((rp - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg)), 4)


def load_external(path):
    d = json.load(open(path, encoding="utf-8"))
    files = [f for f in d["files"] if f.get("drop") is None and "scores" in f]
    return d, files


def load_dev(dev_dir):
    """Out-of-fold scores of the malicious development files, repetition 0, keyed by detector."""
    if not dev_dir:
        return {}
    metas = json.load(open(os.path.join(dev_dir, "file_meta.json"), encoding="utf-8"))
    r0 = json.load(open(os.path.join(dev_dir, "fuse_cv_rep0.json"), encoding="utf-8"))
    out = {}
    for m, probs in r0["prob"].items():
        out[m] = np.array([p for p, meta in zip(probs, metas) if p is not None and int(meta["label"]) == 1], float)
    return out


def threshold_for(scores, target):
    """Smallest threshold t (flag when score >= t) with at most target*n files flagged."""
    s = np.sort(np.asarray(scores, float))[::-1]
    k = int(math.floor(target * len(s)))
    if k >= len(s):
        return 0.0
    return float(np.nextafter(s[k], np.inf))         # just above the (k+1)-th highest score


def analyse(files, dev):
    res = {}
    grid = np.round(np.arange(0.0, 1.0001, 0.05), 2)
    for det in DETECTORS:
        all_s = np.array([f["scores"][det] for f in files if det in f["scores"]], float)
        if not len(all_s):
            continue
        ver_s = np.array([f["scores"][det] for f in files if det in f["scores"] and not f.get("cap_reason")], float)
        dv = dev.get(det)
        r = {"n_all": int(len(all_s)), "n_verified": int(len(ver_s)),
             "quantiles_all": {q: round(float(np.quantile(all_s, q)), 4) for q in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0)},
             "flagged_at_0.5_all": int((all_s >= 0.5).sum()),
             "flagged_at_0.5_verified": int((ver_s >= 0.5).sum()),
             "sweep_verified": [], "targets_verified": {}}
        for t in grid:
            k = int((ver_s >= t).sum())
            row = {"tau": float(t), "flagged": k, "rate": round(k / len(ver_s), 4) if len(ver_s) else None,
                   "wilson95": wilson(k, len(ver_s))}
            if dv is not None and len(dv):
                row["dev_recall"] = round(float((dv >= t).mean()), 4)
            r["sweep_verified"].append(row)
        for tg in TARGETS:
            t = threshold_for(ver_s, tg)
            k = int((ver_s >= t).sum())
            entry = {"tau": round(t, 6), "flagged": k, "n": int(len(ver_s))}
            if dv is not None and len(dv):
                entry["dev_recall"] = round(float((dv >= t).mean()), 4)
                entry["dev_recall_wilson95"] = wilson(int((dv >= t).sum()), len(dv))
            r["targets_verified"][f"{int(tg * 100)}%"] = entry
        if dv is not None and len(dv):
            r["cross_source_auc_verified"] = auc(ver_s, dv)
        res[det] = r
    return res


def to_md(meta, res):
    L = ["# Official checkpoints: threshold sweep (exploratory)", "",
         f"Scored {meta.get('n_scored')} of {meta.get('n_listed')} listed checkpoints. "
         "Rates are on verified files (within the read caps). Development recall is out-of-fold "
         f"(run in {meta.get('_dev_dir', '?')}), malicious files only, and indicative.", "",
         "| Detector | flagged at 0.5 (verified) | threshold for <=5% flagged | dev recall there | "
         "threshold for 0 flagged | dev recall there | cross-source AUC |",
         "|---|---|---|---|---|---|---|"]
    for det, r in res.items():
        t5, t0 = r["targets_verified"]["5%"], r["targets_verified"]["0%"]
        L.append(f"| {det} | {r['flagged_at_0.5_verified']}/{r['n_verified']} | {t5['tau']:.4f} | "
                 f"{t5.get('dev_recall', '-')} | {t0['tau']:.4f} | {t0.get('dev_recall', '-')} | "
                 f"{r.get('cross_source_auc_verified', '-')} |")
    agree = meta.get("agreement_with_stored_verdicts") or {}
    if agree:
        L += ["", "Agreement of this re-scoring with the released pre-registered verdicts at the same thresholds:", ""]
        L += [f"- {row}: {a['same']}/{a['n']} identical (alarms now {a['alarms_now']}, stored {a['alarms_stored']})"
              for row, a in agree.items()]
    return "\n".join(L) + "\n"


def figure(files, dev, res, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False})
    dets = [d for d in ("FUSE", "FUSE-INV", "SP-RF", "SP-CB", "META") if d in res]
    colours = dict(zip(dets, ("#0072B2", "#56B4E9", "#D55E00", "#E69F00", "#009E73")))
    styles = dict(zip(dets, ("-", "--", "-", "--", ":")))
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.0, 2.8))
    for d in dets:
        s = np.sort([f["scores"][d] for f in files if d in f["scores"] and not f.get("cap_reason")])
        a.step(s, 1 - np.arange(len(s)) / len(s), where="post", color=colours[d], ls=styles[d], lw=1.2, label=d)
    a.axvline(0.5, color="0.5", lw=0.8)
    a.set_xlabel("Detector score on official checkpoint")
    a.set_ylabel("Fraction flagged at threshold")
    a.set_title("(a) False-alarm rate against threshold", loc="left", fontsize=8)
    a.legend(frameon=False, fontsize=7)
    for d in dets:
        sw = res[d]["sweep_verified"]
        if "dev_recall" not in sw[0]:
            continue
        xs = [r["dev_recall"] for r in sw]
        ys = [r["rate"] for r in sw]
        b.plot(xs, ys, color=colours[d], ls=styles[d], lw=1.2, label=d)
        p = next(r for r in sw if abs(r["tau"] - 0.5) < 1e-9)
        b.plot(p["dev_recall"], p["rate"], "o", color=colours[d], ms=3)
    b.set_xlabel("Development recall (out-of-fold)")
    b.set_ylabel("False-alarm rate on official checkpoints")
    b.set_title("(b) Trade-off as the threshold moves (dot: 0.5)", loc="left", fontsize=8)
    fig.tight_layout()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fig.savefig(path)
    fig.savefig(os.path.splitext(path)[0] + ".png", dpi=300)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scores", required=True)
    ap.add_argument("--dev-dir", default=os.path.join("app", "experiments_v2", "results", "fuse", "v2"))
    ap.add_argument("--out-dir", default=os.path.join("app", "experiments_v2", "results", "official_scores"))
    ap.add_argument("--fig")
    a = ap.parse_args()
    meta, files = load_external(a.scores)
    meta["_dev_dir"] = a.dev_dir
    dev = load_dev(a.dev_dir if a.dev_dir and os.path.isdir(a.dev_dir) else None)
    res = analyse(files, dev)
    os.makedirs(a.out_dir, exist_ok=True)
    json.dump({"note": "exploratory", "n_files": len(files), "agreement_with_stored_verdicts":
               meta.get("agreement_with_stored_verdicts"), "detectors": res},
              open(os.path.join(a.out_dir, "official_threshold_sweep.json"), "w", encoding="utf-8"), indent=1)
    md = to_md(meta, res)
    open(os.path.join(a.out_dir, "official_threshold_sweep.md"), "w", encoding="utf-8").write(md)
    print(md)
    if a.fig:
        figure(files, dev, res, a.fig)
        print("figure written:", a.fig)


if __name__ == "__main__":
    main()
