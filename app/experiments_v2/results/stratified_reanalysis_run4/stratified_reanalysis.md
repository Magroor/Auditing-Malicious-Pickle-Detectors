F1 (false alarms), rep 0 out-of-fold, dev set of `v2_results (4)/v2`. Exploratory.

| slice | n benign / mal | ML | CNN | SP-RF | SP-CB | SP-style | META |
|---|---|---|---|---|---|---|---|
| all dev | 493 / 254 | 0.941 (4 FP) | 0.930 (5 FP) | 0.947 (3 FP) | 0.947 (3 FP) | 0.891 (41 FP) | 0.952 (8 FP) |
| container: zip | 405 / 33 | 0.848 (1 FP) | 0.828 (1 FP) | 0.807 (1 FP) | 0.807 (1 FP) | 0.825 (4 FP) | 0.842 (0 FP) |
| container: pickle | 55 / 212 | 0.969 (3 FP) | 0.959 (4 FP) | 0.986 (2 FP) | 0.986 (2 FP) | 0.967 (4 FP) | 0.970 (8 FP) |
| container: other | 33 / 9 | 0.364 (0 FP) | 0.364 (0 FP) | 0.000 (0 FP) | 0.000 (0 FP) | 0.353 (33 FP) | 0.875 (0 FP) |
| size: <=4KB | 60 / 215 | 0.959 (1 FP) | 0.949 (1 FP) | 0.967 (1 FP) | 0.967 (1 FP) | 0.974 (1 FP) | 0.986 (1 FP) |
| size: 4KB-1MB | 351 / 33 | 0.889 (2 FP) | 0.903 (1 FP) | 0.885 (1 FP) | 0.885 (1 FP) | 0.889 (2 FP) | 0.788 (7 FP) |
| size: >1MB | 82 / 6 | 0.444 (1 FP) | 0.364 (3 FP) | 0.444 (1 FP) | 0.444 (1 FP) | 0.167 (38 FP) | 0.500 (0 FP) |
| origin: pickle-curated | 493 / 122 | 0.900 (4 FP) | 0.876 (5 FP) | 0.922 (3 FP) | 0.922 (3 FP) | 0.788 (41 FP) | 0.898 (8 FP) |
| origin: pickle-malwares | 0 / 5 | 0.889 (0 FP) | 0.889 (0 FP) | 0.889 (0 FP) | 0.889 (0 FP) | 0.889 (0 FP) | 1.000 (0 FP) |
| origin: pickle-picklecloak | 0 / 127 | 0.980 (0 FP) | 0.980 (0 FP) | 0.972 (0 FP) | 0.972 (0 FP) | 1.000 (0 FP) | 1.000 (0 FP) |
| without label-noise candidates | 493 / 250 | 0.948 (4 FP) | 0.938 (5 FP) | 0.948 (3 FP) | 0.948 (3 FP) | 0.896 (41 FP) | 0.951 (8 FP) |
| without unverified files | 459 / 236 | 0.959 (4 FP) | 0.950 (4 FP) | 0.974 (3 FP) | 0.974 (3 FP) | 0.950 (7 FP) | 0.955 (8 FP) |
