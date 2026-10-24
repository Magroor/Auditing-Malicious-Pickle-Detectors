"""Section 18.2 benign scale-up: false alarms per library and thresholds calibrated on torchvision.

Input: external_benign_scaleup_scores.json from COLAB_BENIGN_SCALEUP.ipynb (raw scores per detector and
file, with the catalogue source of each file). Optional: development out-of-fold scores, to give the
recall a threshold keeps.

Reports, per detector:
  * false alarms at the fixed threshold 0.5 per library, with Wilson 95 percent intervals, on all scored
    files and on readable files (within the read caps) - the pre-specified section 18.2 estimate;
  * thresholds calibrated on the readable torchvision checkpoints only (at most 0, 1 and 5 percent of
    them flagged) and the false-alarm rate those thresholds give on every other library, which is an
    independent benign test set, with the development recall they keep (indicative);
  * cross-source ROC-AUC per library (library files as negatives, development malicious files as positives).

Usage (from the package root):
  python harness/benign_scaleup_analysis.py --scores verdicts/external/external_benign_scaleup_scores.json
      [--dev-dir app/experiments_v2/results/fuse_rerun/v2] [--out-dir results/benign_scaleup]
      [--fig results/benign_scaleup/figS_benign_scaleup.pdf]
"""
import argparse
import json
import os
import sys

import numpy as np

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from official_threshold_sweep import auc, load_dev, threshold_for, wilson  # noqa: E402

DETECTORS = ("FUSE", "FUSE-INV", "SP-RF", "SP-CB", "META", "ML", "CNN")
TARGETS = (0.0, 0.01, 0.05)
CALIB = "torchvision"


def library(src):
    s = (src or "unknown").lower()
    if s.startswith("torchvision"):
        return "torchvision"
    if s.startswith("openmmlab"):
        return s.replace("openmmlab:", "openmmlab-")
    for key in ("timm", "ultralytics", "detectron2", "whisper", "clip", "torchaudio"):
        if key in s:
            return key
    return s.split()[0]


def load(path):
    d = json.load(open(path, encoding="utf-8"))
    files = [f for f in d["files"] if f.get("drop") is None and "scores" in f]
    for f in files:
        f["library"] = library(f.get("source"))
        f["readable"] = not f.get("cap_reason")
    return d, files


def analyse(files, dev):
    libs = sorted({f["library"] for f in files})
    res = {"libraries": {}, "detectors": {}}
    for lib in libs:
        sub = [f for f in files if f["library"] == lib]
        res["libraries"][lib] = {"n": len(sub), "readable": sum(f["readable"] for f in sub)}
    for det in DETECTORS:
        if not any(det in f["scores"] for f in files):
            continue
        dv = dev.get(det)
        r = {"at_0.5": {}, "calibrated_on_torchvision": {}, "auc": {}}
        for lib in libs:
            sub = [f for f in files if f["library"] == lib and det in f["scores"]]
            ver = [f for f in sub if f["readable"]]
            k_all = sum(f["scores"][det] >= 0.5 for f in sub)
            k_ver = sum(f["scores"][det] >= 0.5 for f in ver)
            r["at_0.5"][lib] = {"all": [k_all, len(sub), wilson(k_all, len(sub))],
                                "readable": [k_ver, len(ver), wilson(k_ver, len(ver))]}
            if dv is not None and len(dv) and ver:
                r["auc"][lib] = auc([f["scores"][det] for f in ver], dv)
        calib = [f["scores"][det] for f in files if f["library"] == CALIB and f["readable"] and det in f["scores"]]
        test = [f for f in files if f["library"] != CALIB and f["readable"] and det in f["scores"]]
        for tg in TARGETS:
            if not calib:
                break
            t = threshold_for(calib, tg)
            k = sum(f["scores"][det] >= t for f in test)
            per_lib = {}
            for lib in libs:
                if lib == CALIB:
                    continue
                sub = [f for f in test if f["library"] == lib]
                kk = sum(f["scores"][det] >= t for f in sub)
                per_lib[lib] = [kk, len(sub), wilson(kk, len(sub))]
            entry = {"tau": round(t, 6), "calib_n": len(calib),
                     "test_flagged": [k, len(test), wilson(k, len(test))], "test_by_library": per_lib}
            if dv is not None and len(dv):
                entry["dev_recall"] = round(float((dv >= t).mean()), 4)
                entry["dev_recall_wilson95"] = wilson(int((dv >= t).sum()), len(dv))
            r["calibrated_on_torchvision"][f"{int(tg * 100)}%"] = entry
        res["detectors"][det] = r
    return res


def to_md(meta, res):
    L = ["# Section 18.2 benign scale-up", "",
         f"Scored {meta.get('n_scored')} of {meta.get('n_listed')} catalogue files (total budget "
         f"{meta.get('budget_gb_total')} GB). Drops: {meta.get('drops')}.", "",
         "| Library | scored | readable |", "|---|---|---|"]
    L += [f"| {lib} | {v['n']} | {v['readable']} |" for lib, v in res["libraries"].items()]
    L += ["", "False alarms at 0.5 on readable files, per library (flagged/n):", "",
          "| Detector | " + " | ".join(res["libraries"]) + " |", "|---|" + "---|" * len(res["libraries"])]
    for det, r in res["detectors"].items():
        L.append(f"| {det} | " + " | ".join(f"{r['at_0.5'][lib]['readable'][0]}/{r['at_0.5'][lib]['readable'][1]}"
                                            for lib in res["libraries"]) + " |")
    L += ["", "Threshold calibrated on readable torchvision files, tested on the readable files of every other library:", "",
          "| Detector | target | tau | torchvision n | other libraries flagged | Wilson 95% | dev recall |",
          "|---|---|---|---|---|---|---|"]
    for det, r in res["detectors"].items():
        for tg, e in r["calibrated_on_torchvision"].items():
            k, n, w = e["test_flagged"]
            L.append(f"| {det} | {tg} | {e['tau']:.4f} | {e['calib_n']} | {k}/{n} | {w} | {e.get('dev_recall', '-')} |")
    agree = meta.get("agreement_torchvision_with_stored") or {}
    if agree:
        L += ["", "Torchvision verdicts against the stored section 15 verdicts: " +
              ", ".join(f"{r} {a['same']}/{a['n']}" for r, a in agree.items())]
    return "\n".join(L) + "\n"


def figure(res, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 8, "axes.spines.top": False, "axes.spines.right": False})
    dets = [d for d in ("FUSE", "FUSE-INV", "SP-RF", "SP-CB", "META") if d in res["detectors"]]
    libs = [l for l in res["libraries"] if res["libraries"][l]["readable"]]
    colours = dict(zip(dets, ("#0072B2", "#56B4E9", "#D55E00", "#E69F00", "#009E73")))
    markers = dict(zip(dets, ("o", "s", "^", "D", "v")))
    fig, (a, b) = plt.subplots(1, 2, figsize=(7.0, 3.6), gridspec_kw={"width_ratios": [1.35, 1]},
                               constrained_layout=True)
    for i, d in enumerate(dets):
        for j, lib in enumerate(libs):
            k, n, w = res["detectors"][d]["at_0.5"][lib]["readable"]
            if not n:
                continue
            y = j + (i - len(dets) / 2) * 0.12
            a.errorbar(k / n, y, xerr=[[k / n - w[0]], [w[1] - k / n]], fmt=markers[d], color=colours[d], ms=3,
                       lw=0.8, label=d if j == 0 else None)
    a.set_yticks(range(len(libs)))
    a.set_yticklabels([f"{l} (n={res['libraries'][l]['readable']})" for l in libs])
    a.set_xlim(-0.02, 1.03)
    a.set_xlabel("False-alarm rate (readable files)")
    a.set_title("(a) Threshold 0.5, per library", loc="left", fontsize=8)
    top = 0.0
    for d in dets:
        e = res["detectors"][d]["calibrated_on_torchvision"].get("5%")
        # a threshold that keeps no development recall means the detector cannot be thresholded this way
        if not e or not e.get("dev_recall"):
            continue
        k, n, w = e["test_flagged"]
        top = max(top, w[1])
        b.errorbar(e["dev_recall"], k / n, yerr=[[k / n - w[0]], [w[1] - k / n]], fmt=markers[d], color=colours[d],
                   ms=4, lw=0.8, label=d)
    others = [l for l in libs if l != CALIB]
    b.axhline(0.05, color="0.5", lw=0.8, ls="--")
    b.set_xlabel("Development recall (out-of-fold)")
    b.set_ylabel("False-alarm rate on " + (", ".join(others) if len(others) <= 2 else "the other libraries"))
    b.set_title("(b) Calibrated on torchvision", loc="left", fontsize=8)
    b.set_xlim(-0.02, 1.03)
    b.set_ylim(-0.01, max(0.4, top + 0.05))
    handles, labels = a.get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside upper center", ncol=len(labels), frameon=False, fontsize=7)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fig.savefig(path)
    fig.savefig(os.path.splitext(path)[0] + ".png", dpi=300)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scores", required=True)
    ap.add_argument("--dev-dir", default=os.path.join("app", "experiments_v2", "results", "fuse_rerun", "v2"))
    ap.add_argument("--out-dir", default=os.path.join("results", "benign_scaleup"))
    ap.add_argument("--fig")
    a = ap.parse_args()
    meta, files = load(a.scores)
    dev = load_dev(a.dev_dir if a.dev_dir and os.path.isdir(a.dev_dir) else None)
    res = analyse(files, dev)
    os.makedirs(a.out_dir, exist_ok=True)
    json.dump({"note": "section 18.2 benign scale-up; calibration analyses exploratory", **res},
              open(os.path.join(a.out_dir, "benign_scaleup_analysis.json"), "w", encoding="utf-8"), indent=1)
    md = to_md(meta, res)
    open(os.path.join(a.out_dir, "benign_scaleup_analysis.md"), "w", encoding="utf-8").write(md)
    print(md)
    if a.fig:
        figure(res, a.fig)
        print("figure written:", a.fig)


if __name__ == "__main__":
    main()
