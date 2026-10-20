# Official benign checkpoints (PREREGISTRATION 15)

Listed 166, scored 166. Drops: {}.

| Row | False alarms | Wilson 95% |
|---|---|---|
| CNN@0.5 | 136/166 | [0.7537, 0.8704] |
| CNN@0.5+FC | 166/166 | [0.9774, 1.0] |
| CNN@tuned | 136/166 | [0.7537, 0.8704] |
| CNN@tuned+FC | 166/166 | [0.9774, 1.0] |
| FUSE-C@0.5 | 136/166 | [0.7537, 0.8704] |
| FUSE-C@0.5+FC | 166/166 | [0.9774, 1.0] |
| FUSE-INV@0.5 | 125/166 | [0.6822, 0.8124] |
| FUSE-INV@0.5+FC | 155/166 | [0.8853, 0.9626] |
| FUSE@0.5 | 159/166 | [0.9155, 0.9794] |
| FUSE@0.5+FC | 166/166 | [0.9774, 1.0] |
| META@0.5 | 123/166 | [0.6694, 0.8016] |
| META@0.5+FC | 153/166 | [0.8706, 0.9537] |
| ML@0.5 | 120/166 | [0.6504, 0.7854] |
| ML@0.5+FC | 148/166 | [0.8351, 0.9303] |
| ML@tuned | 126/166 | [0.6886, 0.8178] |
| ML@tuned+FC | 154/166 | [0.8779, 0.9582] |
| SP-AE@p95 | 136/166 | [0.7537, 0.8704] |
| SP-AE@p95+FC | 166/166 | [0.9774, 1.0] |
| SP-CB@0.5 | 110/166 | [0.5878, 0.7302] |
| SP-CB@0.5+FC | 140/166 | [0.7804, 0.8908] |
| SP-RF@0.5 | 136/166 | [0.7537, 0.8704] |
| SP-RF@0.5+FC | 166/166 | [0.9774, 1.0] |
| SP-style@tuned | 160/166 | [0.9234, 0.9833] |
| SP-style@tuned+FC | 160/166 | [0.9234, 0.9833] |

McNemar FUSE vs SafePickle (Holm): {"SP-RF@0.5": {"a_right_b_wrong": 0, "a_wrong_b_right": 23, "p_exact": 0.0, "holm": 0.0}, "SP-CB@0.5": {"a_right_b_wrong": 0, "a_wrong_b_right": 49, "p_exact": 0.0, "holm": 0.0}}
Wording rule (15.3): **FUSE worse than SafePickle (more false alarms)**

Three-way: UNVERIFIED 30 {'byte_cap': 30}
