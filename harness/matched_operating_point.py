"""Matched operating point for the adaptive study (exploratory, supplement Table S12).

Recomputed from the released per-variant records only: scores, axes, seeds and hashes. Nothing here
generates, mutates or loads a pickle.

For each detector the threshold is set just above the k-th highest score of the 20 benign official
checkpoints that the adaptive run scored (axis "benign"), so that exactly k of them are flagged
(k = 0, 1, 2). A unit is a (base file, seed) pair whose variant keeps a live payload. The unit is
detected on an axis when every variant of that unit on that axis stays above the threshold, which is the
same worst-case rule as the budget sweep.

Usage:
    python harness/matched_operating_point.py --records verdicts/adaptive/records.jsonl [--out mop.json]
"""
import argparse
import collections
import json
import math

AXES = ("A-pad", "A-live", "A-meta", "A-name", "A-inject")
DETECTORS = ("FUSE", "SP-RF", "SP-CB", "META", "FUSE-INV")


def wilson(k, n, z=1.959964):
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (round((c - h) / d, 4), round((c + h) / d, 4))


def analyse(records):
    benign = collections.defaultdict(list)
    for r in records:
        if r["axis"] == "benign":
            benign[r["detector"]].append(r["final_score"])
    out = {}
    for det in DETECTORS:
        scores = sorted(benign[det])
        n = len(scores)
        units = collections.defaultdict(list)
        for r in records:
            if r["detector"] == det and r["axis"] != "benign" and r["has_live_reduce"]:
                units[(r["base_file_sha"], r["seed"], r["axis"])].append(r["final_score"])
        res = {"n_benign": n}
        for k in (0, 1, 2):
            if not n:
                continue
            tau = scores[-1 - k] + 1e-9
            row = {"tau": round(tau, 4), "benign_flagged": "%d/%d" % (sum(s > tau for s in scores), n)}
            for ax in AXES:
                cells = [v for (b, s, a), v in units.items() if a == ax]
                det_units = sum(1 for v in cells if min(v) > tau)
                row[ax] = {"detected": det_units, "units": len(cells),
                           "rate": round(det_units / len(cells), 3) if cells else None,
                           "wilson95": wilson(det_units, len(cells))}
            res["k=%d" % k] = row
        out[det] = res
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--records", default="verdicts/adaptive/records.jsonl")
    ap.add_argument("--out")
    a = ap.parse_args()
    with open(a.records, encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    res = analyse(records)
    print("Matched operating point, k = 0 of 20 benign checkpoints flagged (detection rate per axis)")
    print("| Detector | tau | " + " | ".join(AXES) + " |")
    print("|---|---|" + "---|" * len(AXES))
    for det, r in res.items():
        row = r.get("k=0")
        if row:
            print("| %s | %.4f | %s |" % (det, row["tau"], " | ".join("%.3f" % row[ax]["rate"] for ax in AXES)))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=1)


if __name__ == "__main__":
    main()
