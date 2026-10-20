# COLAB_FUSE results (PREREGISTRATION section 11)

Received 2026-10-05 (`v2_results_fuse.zip`, sha256 `ea0e8125…`). Bundle `7f8c2478` (the commit that added
`fuse_eval.py`, before the audit fixes F-92/F-93; neither changes any decision below). JSON only was read,
nothing was unpickled. Locked manifest `1aaa27a4…` reproduced; the locked 139 files were **not scored**
(no `final_locked_results.json`). Dev CV ran on the run-3 folds (`sp_rf_agreement_with_saved` = 1.0 in all
five repetitions, so FUSE is paired with the saved ML/CNN predictions).

## Dev 5x5 grouped CV (747 files), repetition 0 pooled out-of-fold

| Detector | F1 | Precision | Recall | Specificity | FP | FN | AUC | mean fold F1 (25) | F1 +FC |
|---|---|---|---|---|---|---|---|---|---|
| **FUSE** | **0.9551** | 0.9915 | 0.9213 | 0.9959 | 2 | 20 | 0.9842 | 0.9617 ± 0.027 | 0.8973 |
| FUSE-INV | 0.9383 | 0.9828 | 0.8976 | 0.9919 | 4 | 26 | 0.9798 | 0.9338 ± 0.025 | 0.9081 |
| FUSE-C | 0.9231 | 0.9780 | 0.8740 | 0.9899 | 5 | 32 | 0.9819 | 0.9377 ± 0.029 | 0.8918 |
| SP-RF | 0.9489 | 0.9872 | 0.9134 | 0.9939 | 3 | 22 | 0.9805 | 0.9419 ± 0.026 | 0.9162 |
| SP-CB | 0.9467 | 0.9872 | 0.9094 | 0.9939 | 3 | 23 | 0.9841 | 0.9445 ± 0.026 | 0.9142 |
| META | 0.9520 | 0.9675 | 0.9370 | 0.9838 | 8 | 16 | 0.9748 | 0.9491 ± 0.031 | 0.8976 |
| ML (ensemble) | 0.9405 | 0.9828 | 0.9016 | 0.9919 | 4 | 25 | 0.9783 | 0.9358 ± 0.036 | 0.9002 |
| CNN | 0.9342 | 0.9784 | 0.8937 | 0.9899 | 5 | 27 | 0.9730 | 0.9344 ± 0.027 | 0.8994 |

Non-inferiority (margin −0.02 F1, one-sided 95 % bootstrap, Holm over SP-RF/SP-CB):
- **FUSE**: lower bound −0.0108 vs SP-RF (p 0.0036), −0.0085 vs SP-CB (p 0.0014): **non-inferior to both after Holm**; specificity non-inferior to both.
- **FUSE-INV**: lower bound −0.0206 vs SP-RF (p 0.0528, **fails**), −0.0174 vs SP-CB (p 0.0196, Holm 0.0392 — passes only vs SP-CB); specificity NI fails.
- **FUSE-C**: fails (−0.0394 / −0.0369) and is significantly **worse** than SP-RF (ΔF1 −0.0258 [−0.0423, −0.0108], p 0.0004).

Superiority: FUSE vs SP-RF ΔF1 +0.0062 [−0.0133, +0.0264], p 0.61; vs SP-CB +0.0084, p 0.46; vs META +0.0031, p 0.75; vs CNN +0.0209, p 0.066. **No superiority.**

By container (rep 0): FUSE detects 7 of the 9 "other"-container malicious files (SafePickle 0, META 7, FUSE-INV 0, FUSE-C 0). The gain over FUSE-C and FUSE-INV comes from the META features: FUSE's accuracy rests partly on file shape.

## Out-of-fold attack study (existing families A1/A1b/A3/A9, CNN off)

| Seed | files (kept variants) | pairs | FUSE | FUSE-INV | FUSE-C | SP-RF | SP-CB | META | ML |
|---|---|---|---|---|---|---|---|---|---|
| 0 | 35 | 743 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 1 | 34 | 717 | 0 | **1** (A3, live call) | 0 | 0 | 0 | 0 | 0 |

Files evaded. FUSE-INV's one evasion is an A3 live insertion, which Theorem 1 does not cover; it is never evaded by the inert families A1/A1b/A9 (1,416 inert pairs over both seeds), as the proof predicts.

## PREREGISTRATION 11.4 decision (logged 2026-10-05, before the final run)

- **FUSE: ADOPTED.** (a) non-inferior to SP-RF and SP-CB after Holm, (b) specificity 0.9959 ≥ SP-RF 0.9939, (c) 0 evaded files in both seeds = SP-RF.
- **FUSE-INV: NOT ADOPTED.** Fails (a) against SP-RF and (c) in seed 1.
- Consequence under 11.5: the paper may not rest a robustness claim on the invariance proof for the adopted detector, because FUSE includes features outside the canonical form. Any "robust" wording is limited to (i) locked-test non-inferiority, (ii) zero evaded files in the measured families and (iv) the fail-closed cost. FUSE is not superior to SafePickle or META.
