# Cap audit (experiments_v2/v2_results (4)/v2)

Locked manifest `1aaa27a4...` reproduced; dev 747 files, 139 locked files excluded, 5 reps x 5 folds; 225 saved fold F1 values reproduced. Exploratory, dev only.

## Unverified files (meta_baseline.cap_reason)

| reason | dev benign | dev malicious | all benign | all malicious |
|---|---|---|---|---|
| byte_cap | 33 | 2 | 38 | 2 |
| op_cap | 1 | 0 | 1 | 0 |
| malformed | 0 | 16 | 0 | 25 |
| verified | 459 | 236 | 551 | 391 |

Dev byte_cap by container: other/benign 33, other/malicious 2

## Saved verdicts on unverified dev files (flagged per rep, reps 0-4)

| detector | byte_cap/benign | byte_cap/malicious | op_cap/benign | malformed/malicious |
|---|---|---|---|---|
| ML | [0, 0, 0, 0, 0] of 33 | [0, 0, 0, 0, 0] of 2 | [0, 1, 0, 1, 1] of 1 | [8, 8, 8, 8, 9] of 16 |
| CNN | [0, 2, 1, 2, 1] of 33 | [0, 0, 0, 0, 0] of 2 | [1, 1, 1, 1, 1] of 1 | [8, 8, 8, 8, 10] of 16 |
| CNN@0.5 | [3, 4, 7, 2, 3] of 33 | [0, 0, 0, 0, 0] of 2 | [1, 1, 1, 1, 1] of 1 | [8, 9, 9, 9, 10] of 16 |
| SP-RF | [0, 0, 0, 0, 0] of 33 | [0, 0, 0, 0, 0] of 2 | [0, 1, 1, 1, 1] of 1 | [4, 4, 4, 4, 4] of 16 |
| SP-CB | [0, 0, 0, 0, 0] of 33 | [0, 0, 0, 0, 0] of 2 | [0, 1, 1, 1, 1] of 1 | [4, 4, 4, 4, 4] of 16 |
| SP-AE | [0, 0, 0, 0, 0] of 33 | [0, 0, 0, 0, 0] of 2 | [1, 1, 1, 1, 1] of 1 | [5, 5, 5, 5, 5] of 16 |
| SP-style | [33, 33, 33, 33, 33] of 33 | [2, 2, 2, 2, 2] of 2 | [1, 1, 1, 1, 1] of 1 | [15, 15, 15, 15, 15] of 16 |
| SP-RF-tuned | [0, 0, 0, 0, 0] of 33 | [0, 0, 0, 0, 0] of 2 | [0, 1, 0, 1, 0] of 1 | [4, 4, 4, 4, 4] of 16 |
| SP-RF+synth | [0, 0, 0, 0, 0] of 33 | [0, 0, 0, 0, 0] of 2 | [1, 1, 1, 1, 1] of 1 | [3, 4, 4, 3, 4] of 16 |
| META | [0, 0, 0, 0, 0] of 33 | [0, 0, 0, 0, 0] of 2 | [0, 0, 0, 0, 0] of 1 | [15, 14, 15, 13, 15] of 16 |

## Re-scored saved predictions (rep 0 pooled, and mean fold F1 over all reps x folds)

| detector | policy | TP | FP | FN | F1 | spec | mean fold F1 | dF1 vs as-is [95% CI] | dF1 vs SP-RF as-is [95% CI] |
|---|---|---|---|---|---|---|---|---|---|
| ML | as_is | 229 | 4 | 25 | 0.9405 | 0.9919 | 0.9360 | - | -0.0063 [-0.0216, +0.0088] |
| ML | fc_all | 239 | 38 | 15 | 0.9002 | 0.9229 | 0.8940 | -0.0403 [-0.0633, -0.0166] | -0.0465 [-0.0730, -0.0195] |
| ML | fc_malformed | 237 | 4 | 17 | 0.9576 | 0.9919 | 0.9529 | +0.0171 [+0.0063, +0.0302] | +0.0109 [-0.0063, +0.0294] |
| CNN | as_is | 225 | 5 | 29 | 0.9298 | 0.9899 | 0.9324 | - | -0.0170 [-0.0357, +0.0017] |
| CNN | fc_all | 235 | 38 | 19 | 0.8918 | 0.9229 | 0.8930 | -0.0379 [-0.0605, -0.0146] | -0.0549 [-0.0834, -0.0265] |
| CNN | fc_malformed | 233 | 5 | 21 | 0.9472 | 0.9899 | 0.9488 | +0.0174 [+0.0064, +0.0307] | +0.0004 [-0.0206, +0.0221] |
| CNN@0.5 | as_is | 229 | 8 | 25 | 0.9328 | 0.9838 | 0.9299 | - | -0.0139 [-0.0317, +0.0031] |
| CNN@0.5 | fc_all | 239 | 38 | 15 | 0.9002 | 0.9229 | 0.8955 | -0.0326 [-0.0544, -0.0098] | -0.0465 [-0.0739, -0.0199] |
| CNN@0.5 | fc_malformed | 237 | 8 | 17 | 0.9499 | 0.9838 | 0.9443 | +0.0171 [+0.0063, +0.0302] | +0.0032 [-0.0173, +0.0238] |
| SP-RF | as_is | 231 | 3 | 23 | 0.9467 | 0.9939 | 0.9410 | - | - |
| SP-RF | fc_all | 245 | 37 | 9 | 0.9142 | 0.9249 | 0.9080 | -0.0325 [-0.0565, -0.0077] | -0.0325 [-0.0565, -0.0077] |
| SP-RF | fc_malformed | 243 | 3 | 11 | 0.9720 | 0.9939 | 0.9665 | +0.0253 [+0.0124, +0.0408] | +0.0253 [+0.0124, +0.0408] |
| SP-CB | as_is | 231 | 3 | 23 | 0.9467 | 0.9939 | 0.9445 | - | +0.0000 [+0.0000, +0.0000] |
| SP-CB | fc_all | 245 | 37 | 9 | 0.9142 | 0.9249 | 0.9110 | -0.0325 [-0.0565, -0.0077] | -0.0325 [-0.0565, -0.0077] |
| SP-CB | fc_malformed | 243 | 3 | 11 | 0.9720 | 0.9939 | 0.9700 | +0.0253 [+0.0124, +0.0408] | +0.0253 [+0.0124, +0.0408] |
| SP-AE | as_is | 234 | 26 | 20 | 0.9105 | 0.9473 | 0.9091 | - | -0.0362 [-0.0542, -0.0184] |
| SP-AE | fc_all | 247 | 59 | 7 | 0.8821 | 0.8803 | 0.8779 | -0.0284 [-0.0508, -0.0049] | -0.0646 [-0.0917, -0.0363] |
| SP-AE | fc_malformed | 245 | 26 | 9 | 0.9333 | 0.9473 | 0.9314 | +0.0228 [+0.0103, +0.0376] | -0.0134 [-0.0354, +0.0097] |
| SP-style | as_is | 237 | 41 | 17 | 0.8910 | 0.9168 | 0.8802 | - | -0.0557 [-0.0833, -0.0278] |
| SP-style | fc_all | 238 | 41 | 16 | 0.8931 | 0.9168 | 0.8826 | +0.0021 [+0.0000, +0.0064] | -0.0537 [-0.0809, -0.0260] |
| SP-style | fc_malformed | 238 | 41 | 16 | 0.8931 | 0.9168 | 0.8826 | +0.0021 [+0.0000, +0.0064] | -0.0537 [-0.0809, -0.0260] |
| SP-RF-tuned | as_is | 220 | 2 | 34 | 0.9244 | 0.9959 | 0.9380 | - | -0.0224 [-0.0383, -0.0090] |
| SP-RF-tuned | fc_all | 234 | 36 | 20 | 0.8931 | 0.9270 | 0.9041 | -0.0312 [-0.0557, -0.0058] | -0.0536 [-0.0823, -0.0249] |
| SP-RF-tuned | fc_malformed | 232 | 2 | 22 | 0.9508 | 0.9959 | 0.9638 | +0.0264 [+0.0129, +0.0425] | +0.0041 [-0.0170, +0.0250] |
| SP-RF+synth | as_is | 216 | 4 | 38 | 0.9114 | 0.9919 | 0.9050 | - | -0.0353 [-0.0550, -0.0172] |
| SP-RF+synth | fc_all | 231 | 37 | 23 | 0.8851 | 0.9249 | 0.8761 | -0.0263 [-0.0509, -0.0008] | -0.0617 [-0.0919, -0.0310] |
| SP-RF+synth | fc_malformed | 229 | 4 | 25 | 0.9405 | 0.9919 | 0.9334 | +0.0291 [+0.0149, +0.0460] | -0.0063 [-0.0297, +0.0171] |
| META | as_is | 238 | 8 | 16 | 0.9520 | 0.9838 | 0.9488 | - | +0.0053 [-0.0154, +0.0265] |
| META | fc_all | 241 | 42 | 13 | 0.8976 | 0.9148 | 0.8931 | -0.0544 [-0.0744, -0.0347] | -0.0491 [-0.0765, -0.0215] |
| META | fc_malformed | 239 | 8 | 15 | 0.9541 | 0.9838 | 0.9522 | +0.0021 [+0.0000, +0.0064] | +0.0074 [-0.0129, +0.0282] |

Policies: as_is = saved verdict; fc_all = also flag every unverified file; fc_malformed = also flag malformed files only. Bootstrap: colab_v2_eval.boot_delta_f1, 10000 resamples, seed 0, stratified by class.

## Caveats

- fc_all adds the 34 benign unverified dev files (33 byte_cap, 1 op_cap) as false alarms to every detector that did not already flag them.
- Malformed dev files: 0 benign / 16 malicious (no benign file is malformed, so the fc_malformed gain partly measures a corpus property). Benign joblib files that store numpy arrays also parse as malformed, because joblib writes raw array bytes inside the stream (c2_frontend: decode_error / interleaved_raw_data), so in the wild fc_malformed would cost false alarms that this table cannot show.
- byte_cap files were read as ZERO opcodes by every opcode-based detector here. The C2 front-end (c2_frontend.py) reads the first 16 MiB and verifies files whose loader-run streams end inside it; cap_rescan.py (Colab) measures how many of these files that recovers.
- The bootstrap CIs are per comparison, with no multiplicity correction (exploratory).
