"""Recompute the paper's tables from the released per-file verdicts. Nothing is trained or scored.

    python -I reproduce.py --experiment dev           # development 5x5 CV, repetition 0 (first run)
    python -I reproduce.py --experiment locked_test   # the single locked-test run (139 files)
    python -I reproduce.py --experiment section14     # metadata-hard subset and three-way verdict
    python -I reproduce.py --experiment external      # 166 official torchvision checkpoints: false alarms
    python -I reproduce.py --experiment all

Every number comes from files under app/experiments_v2/results/ and verdicts/. No pickle is loaded or
unpickled, and the locked set is never re-scored. The attack and adaptive-evasion studies are NOT
reproduced here: that tooling is withheld (see README.md).
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EXP = os.path.join(HERE, "app", "experiments_v2")
# python -I drops the script directory from sys.path, so add the code directories explicitly.
for _p in (os.path.join(HERE, "app"), EXP, os.path.join(EXP, "ned2")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def wilson(k, n, z=1.959964):
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def mcnemar_exact(b, c):
    """Two-sided exact binomial McNemar p-value from the discordant counts."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def external(path=os.path.join(HERE, "verdicts", "external", "external_official_benign.json")):
    d = json.load(open(path, encoding="utf-8"))
    files = d["files"]
    n = len(files)
    names = sorted(files[0]["pred"])
    rows, ok = {}, True
    for m in names:
        k = sum(int(f["pred"][m]) for f in files)
        rows[m] = {"false_alarms": k, "n": n, "wilson95": wilson(k, n)}
        stored = d["summary"]["rows"][m]
        ok &= (stored["false_alarms"] == k and stored["wilson95"] == rows[m]["wilson95"])
    mc = {}
    for b in ("SP-RF@0.5", "SP-CB@0.5"):
        a_right_b_wrong = sum(1 for f in files if f["pred"]["FUSE@0.5"] == 0 and f["pred"][b] == 1)
        a_wrong_b_right = sum(1 for f in files if f["pred"]["FUSE@0.5"] == 1 and f["pred"][b] == 0)
        mc[b] = {"fuse_right_other_wrong": a_right_b_wrong, "fuse_wrong_other_right": a_wrong_b_right,
                 "p_exact": mcnemar_exact(a_right_b_wrong, a_wrong_b_right)}
    return {"n": n, "rows": rows, "mcnemar_fuse": mc, "matches_stored_summary": bool(ok),
            "three_way_unverified": d["summary"]["three_way"]["unverified_by_reason"]}


def external_md(r):
    L = [f"## external official benign ({r['n']} checkpoints, download.pytorch.org)", "",
         "| Row | False alarms | Wilson 95% |", "|---|---|---|"]
    L += [f"| {m} | {v['false_alarms']}/{v['n']} | {v['wilson95']} |" for m, v in r["rows"].items()]
    L += ["", f"McNemar (FUSE vs SafePickle): {r['mcnemar_fuse']}",
          f"UNVERIFIED (byte cap): {r['three_way_unverified']}",
          f"Recomputed counts match the stored summary: {r['matches_stored_summary']}", ""]
    return "\n".join(L)


def _load_core():
    """Load app/experiments_v2/reproduce.py by path (it needs numpy, scipy and scikit-learn)."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("reproduce_core", os.path.join(EXP, "reproduce.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main(argv=None):
    ap = argparse.ArgumentParser(description="Recompute the paper tables from released verdicts (no retraining).")
    ap.add_argument("--experiment", choices=["dev", "locked_test", "section14", "external", "all"], default="all")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    a = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # tables contain a minus sign
    names = ["dev", "locked_test", "section14", "external"] if a.experiment == "all" else [a.experiment]
    for n in names:
        if n == "external":
            r = external()
            print(json.dumps(r, indent=1) if a.json else external_md(r))
            continue
        _R = _load_core()
        r = getattr(_R, n)()
        print(json.dumps(r, indent=1, default=str) if a.json else _R.to_md(n, r))


if __name__ == "__main__":
    main()
