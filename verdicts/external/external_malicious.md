# External malicious source (PREREGISTRATION 13)

Manifest `417484adeb5f…`, scored 16. Drops: {'sha_overlap_corpus': 41, 'sha_overlap_pickleball_sealed': 29, 'reject:empty': 1, 'duplicate': 1, 'reject:not_pickle_magic': 1}.

Novel malicious files (no structural group shared with the corpus): 2

| Row | Detected (novel) | Recall Wilson (novel) | Detected (all) | False alarms |
|---|---|---|---|---|
| CNN@0.5 | 2/2 | [0.3424, 1.0] | 15/16 | 0/0 |
| CNN@0.5+FC | 2/2 | [0.3424, 1.0] | 15/16 | 0/0 |
| CNN@tuned | 2/2 | [0.3424, 1.0] | 15/16 | 0/0 |
| CNN@tuned+FC | 2/2 | [0.3424, 1.0] | 15/16 | 0/0 |
| FUSE-C@0.5 | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| FUSE-C@0.5+FC | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| FUSE-INV@0.5 | 2/2 | [0.3424, 1.0] | 15/16 | 0/0 |
| FUSE-INV@0.5+FC | 2/2 | [0.3424, 1.0] | 15/16 | 0/0 |
| FUSE@0.5 | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| FUSE@0.5+FC | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| META@0.5 | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| META@0.5+FC | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| ML@0.5 | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| ML@0.5+FC | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| ML@tuned | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| ML@tuned+FC | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| SP-AE@p95 | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| SP-AE@p95+FC | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| SP-CB@0.5 | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| SP-CB@0.5+FC | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| SP-RF@0.5 | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| SP-RF@0.5+FC | 2/2 | [0.3424, 1.0] | 16/16 | 0/0 |
| SP-style@tuned | 2/2 | [0.3424, 1.0] | 15/16 | 0/0 |
| SP-style@tuned+FC | 2/2 | [0.3424, 1.0] | 15/16 | 0/0 |

McNemar FUSE vs SafePickle on novel malicious files (Holm): {"SP-RF@0.5": {"a_right_b_wrong": 0, "a_wrong_b_right": 0, "p_exact": 1.0, "holm": 1.0}, "SP-CB@0.5": {"a_right_b_wrong": 0, "a_wrong_b_right": 0, "p_exact": 1.0, "holm": 1.0}}
Wording rule (13.5): **comparable**

Three-way: UNVERIFIED 0 {}
