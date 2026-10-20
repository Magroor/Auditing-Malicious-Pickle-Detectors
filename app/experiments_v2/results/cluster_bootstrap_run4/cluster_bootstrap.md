# Cluster vs file-level paired bootstrap (dev, out-of-fold)

Results folder: `v2_results (4)/v2`; locked manifest `1aaa27a4` (asserted). B = 10000, seed 0. META source: {'0': 'recomputed (meta_baseline.fit_meta, identical folds)', '1': 'recomputed (meta_baseline.fit_meta, identical folds)', '2': 'recomputed (meta_baseline.fit_meta, identical folds)', '3': 'recomputed (meta_baseline.fit_meta, identical folds)', '4': 'recomputed (meta_baseline.fit_meta, identical folds)'}. Exploratory.

```
Resampling schemes (B = 10,000, seed 0, percentile intervals, paired: both detectors are evaluated
on the same resample):
  file    : the pre-registered scheme. Malicious files and benign files are resampled with
            replacement separately, class sizes fixed. Same RNG calls in the same order as
            colab_v2_eval.boot_delta_f1 / boot_noninferiority, so the numbers equal stage 4.
  cluster : the unit is the pre-registered group (file_meta "group": hash of the canonical opcode
            sequence + imported globals; unparseable files are their own group). Groups are split
            into strata by the labels of their dev members (all malicious / all benign / mixed),
            and each stratum is resampled with replacement with its number of groups fixed. Every
            dev member of a drawn group enters the resample, so class sizes vary between resamples.
            With singleton groups this is exactly the file scheme (same draws).
  Per resample: F1 = 2TP / (2TP + FP + FN); specificity = 1 - FP / (benign files in the resample).
  Two-sided p = 2 min(share delta <= 0, share delta >= 0) (PREREG s.4). Non-inferiority: one-sided
  95 % lower bound (5th percentile) > margin; p_one_sided = share delta <= margin; Holm over the
  family {vs SP-RF, vs SP-CB} of each candidate (PREREG s.9.1), monotone adjusted p.
```

Clusters: {'n_files': 747, 'n_clusters': 448, 'clusters_per_stratum': {'malicious': 189, 'benign': 255, 'mixed': 4}, 'largest_cluster': 98, 'n_boot': 10000, 'seed': 0}

## Repetition 0 (pre-registered primary repetition)

| comparison | dF1 | file 95% CI | cluster 95% CI | NI F1 LB file / cluster | NI spec LB file / cluster |
|---|---|---|---|---|---|
| ML vs SP-RF | -0.0063 | [-0.0216, 0.0088] | [-0.0236, 0.0094] | -0.0192 (pass) / -0.0204 (fail) | -0.0061 (fail) / -0.0062 (fail) |
| ML vs SP-CB | -0.0063 | [-0.0216, 0.0088] | [-0.0236, 0.0094] | -0.0192 (pass) / -0.0204 (fail) | -0.0061 (fail) / -0.0062 (fail) |
| CNN vs SP-RF | -0.0170 | [-0.0357, 0.0017] | [-0.0399, 0.0029] | -0.0325 (fail) / -0.0358 (fail) | -0.0101 (fail) / -0.0118 (fail) |
| CNN vs SP-CB | -0.0170 | [-0.0357, 0.0017] | [-0.0399, 0.0029] | -0.0325 (fail) / -0.0358 (fail) | -0.0101 (fail) / -0.0118 (fail) |
| CNN@0.5 vs SP-RF | -0.0139 | [-0.0317, 0.0031] | [-0.0336, 0.0042] | -0.0287 (fail) / -0.0303 (fail) | -0.0183 (fail) / -0.0215 (fail) |
| CNN@0.5 vs SP-CB | -0.0139 | [-0.0317, 0.0031] | [-0.0336, 0.0042] | -0.0287 (fail) / -0.0303 (fail) | -0.0183 (fail) / -0.0215 (fail) |
| META vs SP-RF | +0.0053 | [-0.0154, 0.0265] | [-0.016, 0.0274] | -0.0117 (pass) / -0.0124 (pass) | -0.0183 (fail) / -0.0213 (fail) |
| META vs SP-CB | +0.0053 | [-0.0154, 0.0265] | [-0.016, 0.0274] | -0.0117 (pass) / -0.0124 (pass) | -0.0183 (fail) / -0.0213 (fail) |

## All repetitions: reps (of 5) meeting the non-inferiority rule (margins F1 -0.02, specificity -0.005)

| comparison | F1 file | F1 cluster | spec file | spec cluster | CI width ratio cluster/file (F1) |
|---|---|---|---|---|---|
| ML vs SP-RF | 2 | 1 | 2 | 2 | 1.091 |
| ML vs SP-CB | 1 | 0 | 2 | 1 | 1.112 |
| CNN vs SP-RF | 1 | 1 | 1 | 1 | 1.113 |
| CNN vs SP-CB | 0 | 0 | 0 | 0 | 1.109 |
| CNN@0.5 vs SP-RF | 1 | 1 | 1 | 1 | 1.073 |
| CNN@0.5 vs SP-CB | 0 | 0 | 0 | 0 | 1.068 |
| META vs SP-RF | 5 | 4 | 0 | 0 | 1.05 |
| META vs SP-CB | 4 | 4 | 0 | 0 | 1.039 |

NI = one-sided 95 % lower bound of the paired bootstrap delta above the margin (PREREGISTRATION s.9.1); Holm-adjusted p-values over {vs SP-RF, vs SP-CB} are in the JSON.
