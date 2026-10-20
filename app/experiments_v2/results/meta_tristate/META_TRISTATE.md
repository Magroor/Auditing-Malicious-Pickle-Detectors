# Section 14: metadata-hard subset and three-way policy (development, saved predictions)

## 14.1 Metadata-hard subset H (563 of 747 dev files; 71 malicious, 492 benign; 184 bare pickles <= 4 KB removed)

| Detector | F1 (rep 0) | Recall | FP | FN | mean F1 over reps ± SD |
|---|---|---|---|---|---|
| FUSE | 0.8571 | 0.7606 | 1 | 17 | 0.8705 ± 0.0227 |
| FUSE-INV | 0.7967 | 0.6901 | 3 | 22 | 0.7967 ± 0.004 |
| FUSE-C | 0.7179 | 0.5915 | 4 | 29 | 0.7706 ± 0.0298 |
| SP-RF | 0.813 | 0.7042 | 2 | 21 | 0.7909 ± 0.0129 |
| SP-CB | 0.8033 | 0.6901 | 2 | 22 | 0.7961 ± 0.0059 |
| META | 0.8271 | 0.7746 | 7 | 16 | 0.82 ± 0.024 |
| ML | 0.8254 | 0.7324 | 3 | 19 | 0.8236 ± 0.019 |
| CNN | 0.8281 | 0.7465 | 4 | 18 | 0.8267 ± 0.0154 |

| Comparison | ΔF1 [95% CI] | p (bootstrap) | Holm | McNemar (a right / b right, p) |
|---|---|---|---|---|
| FUSE vs SP-RF | +0.0441 [-0.0353, +0.1234] | 0.304 | 0.6080 | 12 / 7, 0.359283 |
| FUSE vs SP-CB | +0.0539 [-0.0225, +0.1324] | 0.196 | 0.5880 | 12 / 6, 0.237885 |
| FUSE vs META | +0.0301 [-0.0439, +0.1028] | 0.4274 | 0.6080 | 13 / 8, 0.38331 |

Wording rule (14.1): **comparable to META on H**.

## 14.2 Three-way policy

UNVERIFIED: 34 benign, 18 malicious (review load 6.9% of benign). By reason: {'byte_cap|benign': 33, 'byte_cap|malicious': 2, 'malformed|malicious': 16, 'op_cap|benign': 1}.

| Detector | F1 verified only | FP verified | Policy recall [Wilson] | As built F1 |
|---|---|---|---|---|
| FUSE | 0.9561 | 2 | 0.9291 [0.8908, 0.9547] | 0.9551 |
| FUSE-INV | 0.9676 | 3 | 0.9528 [0.9193, 0.9728] | 0.9383 |
| FUSE-C | 0.9497 | 4 | 0.9252 [0.8861, 0.9516] | 0.9231 |
| SP-RF | 0.9764 | 3 | 0.9685 [0.9391, 0.984] | 0.9489 |
| SP-CB | 0.9742 | 3 | 0.9646 [0.934, 0.9812] | 0.9467 |
| META | 0.955 | 8 | 0.9488 [0.9144, 0.9698] | 0.952 |
| ML | 0.9588 | 4 | 0.9409 [0.9049, 0.9639] | 0.9405 |
| CNN | 0.9584 | 2 | 0.9331 [0.8954, 0.9578] | 0.9342 |
