# Section 18.2 benign scale-up

Scored 228 of 2823 catalogue files (total budget 80.0 GB). Drops: {'budget_skipped': 2595}.

| Library | scored | readable |
|---|---|---|
| timm | 62 | 62 |
| torchvision | 166 | 136 |

False alarms at 0.5 on readable files, per library (flagged/n):

| Detector | timm | torchvision |
|---|---|---|
| FUSE | 62/62 | 136/136 |
| FUSE-INV | 61/62 | 125/136 |
| SP-RF | 62/62 | 136/136 |
| SP-CB | 62/62 | 110/136 |
| META | 61/62 | 123/136 |
| ML | 57/62 | 118/136 |
| CNN | 62/62 | 136/136 |

Threshold calibrated on readable torchvision files, tested on the readable files of every other library:

| Detector | target | tau | torchvision n | other libraries flagged | Wilson 95% | dev recall |
|---|---|---|---|---|---|---|
| FUSE | 0% | 0.9837 | 136 | 0/62 | [0.0, 0.0583] | 0.7795 |
| FUSE | 1% | 0.9818 | 136 | 0/62 | [0.0, 0.0583] | 0.7795 |
| FUSE | 5% | 0.9706 | 136 | 8/62 | [0.0669, 0.2345] | 0.815 |
| FUSE-INV | 0% | 0.9950 | 136 | 0/62 | [0.0, 0.0583] | 0.6063 |
| FUSE-INV | 1% | 0.9950 | 136 | 0/62 | [0.0, 0.0583] | 0.6063 |
| FUSE-INV | 5% | 0.9908 | 136 | 13/62 | [0.1268, 0.3264] | 0.6811 |
| SP-RF | 0% | 1.0000 | 136 | 0/62 | [0.0, 0.0583] | 0.0 |
| SP-RF | 1% | 0.9900 | 136 | 0/62 | [0.0, 0.0583] | 0.5945 |
| SP-RF | 5% | 0.9800 | 136 | 0/62 | [0.0, 0.0583] | 0.6614 |
| SP-CB | 0% | 0.9790 | 136 | 5/62 | [0.0349, 0.1753] | 0.7165 |
| SP-CB | 1% | 0.9790 | 136 | 5/62 | [0.0349, 0.1753] | 0.7165 |
| SP-CB | 5% | 0.9790 | 136 | 5/62 | [0.0349, 0.1753] | 0.7165 |
| META | 0% | 1.0000 | 136 | 0/62 | [0.0, 0.0583] | 0.0 |
| META | 1% | 1.0000 | 136 | 0/62 | [0.0, 0.0583] | 0.0 |
| META | 5% | 1.0000 | 136 | 0/62 | [0.0, 0.0583] | 0.0 |
| ML | 0% | 0.9010 | 136 | 0/62 | [0.0, 0.0583] | 0.752 |
| ML | 1% | 0.9010 | 136 | 0/62 | [0.0, 0.0583] | 0.752 |
| ML | 5% | 0.8712 | 136 | 0/62 | [0.0, 0.0583] | 0.7874 |
| CNN | 0% | 0.9996 | 136 | 0/62 | [0.0, 0.0583] | 0.7283 |
| CNN | 1% | 0.9996 | 136 | 0/62 | [0.0, 0.0583] | 0.7283 |
| CNN | 5% | 0.9879 | 136 | 0/62 | [0.0, 0.0583] | 0.8268 |

Torchvision verdicts against the stored section 15 verdicts: ML@tuned 166/166, ML@0.5 166/166, CNN@tuned 166/166, CNN@0.5 166/166, SP-style@tuned 166/166, SP-RF@0.5 166/166, SP-CB@0.5 166/166, SP-AE@p95 166/166, META@0.5 166/166, FUSE@0.5 166/166, FUSE-C@0.5 166/166, FUSE-INV@0.5 166/166
