#!/usr/bin/env python3
"""
adaptive_stats.py  --  turns adaptive_score.py records into the paper numbers.

Reads records.jsonl and emits, per detector and attack axis, under each of the
three policies (fail-open / fail-closed / three-way):
  - detection rate DR = 1 - evaded / n, with Wilson 95% CI
  - evaded count with Wilson UPPER bound (so "0 of N" is never read as proof)
  - within-cap vs cap evasions, reported separately (a unit can be in both)
  - first-evasion budget distribution among evaded units
Plus the benign FPR per detector per policy (axis=="benign") with Wilson CI,
and the unverified fraction under the three-way policy.

UNIT (PREREGISTRATION 18.3)
---------------------------
`base_files` and `evaded_files` count (base_file_sha, seed) trajectories that
still carry the payload, not unique files. One file attacked with five seeds is
five units. A unit is an evasion when any payload-preserving variant on it is
SAFE under that policy. A unit whose variants all dropped the payload is not in
the denominator. A unit with no verified verdict (unwired detector, non-finite
score, or unreadable under three-way) is not counted as a detection.

Nothing here generates or mutates a pickle. Pure aggregation of records.

Run:
  python3 -I adaptive_stats.py --records records.jsonl --out results.json
"""
import argparse, json, math, statistics, sys


def wilson(k, n, z=1.96):
    if n <= 0:
        return 0.0, 0.0, 0.0
    if k < 0 or k > n:
        raise ValueError(f"wilson count {k} outside 0..{n}")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def _as_float(x):
    """Finite number, or None. Booleans are not scores (bool is a subclass of int)."""
    if isinstance(x, bool) or x is None:
        return None
    if isinstance(x, (int, float)):
        xf = float(x)
    elif isinstance(x, str):
        try:
            xf = float(x.strip())
        except ValueError:
            return None
    else:
        return None
    if not math.isfinite(xf):
        return None
    return xf


def _bad_score(rec):
    """True when a score was supplied but cannot be thresholded."""
    s = rec.get("final_score", None)
    if s is None:
        return False
    return _as_float(s) is None


def verdict(rec, policy):
    """SAFE / MALICIOUS / UNVERIFIED for a record under a policy.

    final_score None (detector not wired, or a non-finite score) -> UNVERIFIED.
    A non-finite score must not fall through to SAFE: NaN >= threshold is false,
    which would count a broken model as an evasion.
    """
    s = _as_float(rec.get("final_score", None))
    thr = _as_float(rec.get("threshold", None))
    if s is None or thr is None:
        return "UNVERIFIED"
    if "readable" not in rec or "over_cap" not in rec:
        # Fail-open only needs the score. Cap policies cannot be applied blindly.
        if policy == "fail-open":
            return "MALICIOUS" if s >= thr else "SAFE"
        return "UNVERIFIED"
    unreadable = (not rec["readable"]) or bool(rec["over_cap"])
    if policy == "fail-open":
        return "MALICIOUS" if s >= thr else "SAFE"
    if policy == "fail-closed":
        if unreadable:
            return "MALICIOUS"
        return "MALICIOUS" if s >= thr else "SAFE"
    if policy == "three-way":
        if unreadable:
            return "UNVERIFIED"
        return "MALICIOUS" if s >= thr else "SAFE"
    raise ValueError(policy)


POLICIES = ["fail-open", "fail-closed", "three-way"]


def _json_num(x):
    if x is None:
        return None
    xf = float(x)
    if not math.isfinite(xf):
        return None
    if xf.is_integer():
        return int(xf)
    return xf


def _budget(rec):
    bd = rec.get("budget_or_blocks")
    if isinstance(bd, bool) or not isinstance(bd, (int, float)):
        return None
    if isinstance(bd, float) and not math.isfinite(bd):
        return None
    return bd


def _null_attack(n_units, unverified):
    return {
        "base_files": n_units, "evaded_files": None,
        "detection_rate": None, "dr_wilson95": None,
        "evaded_wilson95_upper": None,
        "within_cap_evaded_files": None, "cap_evaded_files": None,
        "unverified_records": unverified, "unverified_units": n_units,
        "first_evasion_budget": {"n": None, "min": None, "median": None, "max": None},
    }


def _attack_cell(sub, pol):
    """One detector x axis x policy. `sub` is payload-preserving records only."""
    if not sub:
        # No feasible variant. 0/0 must not be reported as a 0% detection rate.
        return _null_attack(0, 0)

    units = {}
    for r in sub:
        sha = r.get("base_file_sha")
        if not isinstance(sha, str) or not sha:
            continue
        units.setdefault((sha, r.get("seed")), []).append(r)

    unverified = 0
    verified_n = 0
    evaded, within_cap, cap = set(), set(), set()
    first_budget = {}
    for key, rs in units.items():
        verified = []
        for r in rs:
            v = verdict(r, pol)
            if v == "UNVERIFIED":
                unverified += 1
            else:
                verified.append((r, v))
        if not verified:
            continue
        verified_n += 1
        safe = [r for r, v in verified if v == "SAFE"]
        if not safe:
            continue
        evaded.add(key)
        for r in safe:
            oc = r.get("over_cap", None)
            if oc is True:
                cap.add(key)
            elif oc is False:
                within_cap.add(key)
        budgets = [b for b in (_budget(r) for r in safe) if b is not None]
        if budgets:
            first_budget[key] = min(budgets)

    if verified_n == 0:
        # Every trajectory was unverified, or none had a usable id. A 0/0 rate
        # would read as "detected nothing".
        return _null_attack(len(units), unverified)

    nfiles = verified_n
    nev = len(evaded)
    dr, dr_lo, dr_hi = wilson(nfiles - nev, nfiles)
    _, _, ev_hi = wilson(nev, nfiles)
    budgets = sorted(first_budget.values())
    return {
        "base_files": nfiles,
        "evaded_files": nev,
        "detection_rate": round(dr, 4),
        "dr_wilson95": [round(dr_lo, 4), round(dr_hi, 4)],
        "evaded_wilson95_upper": round(ev_hi, 4),
        "within_cap_evaded_files": len(within_cap),
        "cap_evaded_files": len(cap),
        "unverified_records": unverified,
        "unverified_units": len(units) - verified_n,
        "first_evasion_budget": {
            "n": len(budgets),
            "min": _json_num(budgets[0]) if budgets else None,
            "median": _json_num(statistics.median(budgets)) if budgets else None,
            "max": _json_num(budgets[-1]) if budgets else None,
        },
    }


def _null_benign(n_files, unverified):
    return {
        "n_benign": n_files, "false_alarms": None,
        "fpr": None, "fpr_wilson95": None,
        "unverified_records": unverified,
    }


def _benign_cell(sub, pol):
    units = {}
    for r in sub:
        sha = r.get("base_file_sha")
        if not isinstance(sha, str) or not sha:
            continue
        units.setdefault(sha, []).append(r)
    unverified = 0
    verified_n = 0
    flagged = 0
    for rs in units.values():
        saw = False
        alarm = False
        for r in rs:
            v = verdict(r, pol)
            if v == "UNVERIFIED":
                unverified += 1
            else:
                saw = True
                if v == "MALICIOUS":
                    alarm = True
        if not saw:
            continue
        verified_n += 1
        if alarm:
            flagged += 1
    if not units or verified_n == 0:
        return _null_benign(len(units), unverified)
    fpr, lo, hi = wilson(flagged, verified_n)
    return {
        "n_benign": verified_n, "false_alarms": flagged,
        "fpr": round(fpr, 6), "fpr_wilson95": [round(lo, 6), round(hi, 6)],
        "unverified_records": unverified,
        "unverified_files": len(units) - verified_n,
    }


def _load_records(path):
    recs = []
    bad = []
    last_no = 0
    with open(path, encoding="utf-8") as fh:
        for last_no, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                bad.append((last_no, str(exc)))
                continue
            if not isinstance(obj, dict):
                bad.append((last_no, "line is not a JSON object"))
                continue
            recs.append(obj)
    note = None
    if bad:
        earlier = [b for b in bad if b[0] != last_no]
        if earlier or not recs:
            first = bad[0]
            sys.exit(f"records JSONL has {len(bad)} unreadable line(s); "
                     f"first is line {first[0]}: {first[1]}")
        note = f"ignored truncated final record at line {bad[0][0]}"
    return recs, note


def aggregate(recs):
    notes = []
    atk, ben = [], []
    skipped = 0
    for r in recs:
        axis = r.get("axis")
        if axis == "benign":
            ben.append(r)
            continue
        if not isinstance(axis, str) or not isinstance(r.get("detector"), str):
            skipped += 1
            continue
        atk.append(r)
    if skipped:
        notes.append(f"skipped {skipped} attack records missing detector or axis")

    results = {
        "adaptive": {},
        "benign_fpr": {},
        "notes": notes,
        "unit": "(base_file_sha, seed)",
    }

    dets = sorted({r["detector"] for r in atk})
    axes = sorted({r["axis"] for r in atk})
    sha_skips = 0
    for det in dets:
        results["adaptive"][det] = {}
        for ax in axes:
            sub = [r for r in atk
                   if r["detector"] == det and r["axis"] == ax
                   and r.get("has_live_reduce") is True]
            sha_skips += sum(1 for r in sub
                             if not isinstance(r.get("base_file_sha"), str) or not r.get("base_file_sha"))
            per_policy = {pol: _attack_cell(sub, pol) for pol in POLICIES}
            results["adaptive"][det][ax] = per_policy
    if sha_skips:
        notes.append(f"skipped {sha_skips} payload-preserving records with no base_file_sha")

    if ben:
        for det in sorted({r.get("detector") for r in ben if isinstance(r.get("detector"), str)}):
            sub = [r for r in ben if r.get("detector") == det]
            results["benign_fpr"][det] = {pol: _benign_cell(sub, pol) for pol in POLICIES}

    unwired = []
    by_det = {}
    for r in recs:
        det = r.get("detector")
        if isinstance(det, str):
            by_det.setdefault(det, []).append(r)
    for det in sorted(by_det):
        rs = by_det[det]
        if rs and all(r.get("final_score") is None for r in rs) and all(
                r.get("note") == "detector_not_wired" or r.get("threshold") is None
                for r in rs):
            unwired.append(det)
    if unwired:
        notes.append(f"detectors not wired, reported as null: {unwired}")

    bad_scores = sorted({r["detector"] for r in recs
                         if isinstance(r.get("detector"), str) and (
                             _bad_score(r) or r.get("note") in ("non_finite_score", "non_numeric_score")
                         )})
    if bad_scores:
        notes.append("non-numeric or non-finite scores treated as unverified: "
                     + str(bad_scores))
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--records", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    recs, trunc = _load_records(args.records)
    results = aggregate(recs)
    if trunc:
        results["notes"].append(trunc)

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, allow_nan=False)
        fh.write("\n")
    print(f"wrote {args.out}: {len(results['adaptive'])} detectors, "
          f"{len(results['benign_fpr'])} benign rows, unit={results['unit']}")
    if results["notes"]:
        print("notes:", " | ".join(results["notes"]))


if __name__ == "__main__":
    main()
