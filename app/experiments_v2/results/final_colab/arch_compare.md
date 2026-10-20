# Architecture comparison (PREREGISTRATION 12.1, exploratory)

| Encoder | F1 | Precision | Recall | Specificity | AUC | Params | Train s (5 folds) | CPU ms/file |
|---|---|---|---|---|---|---|---|---|
| CNN | 0.9347 | 0.9703 | 0.9016 | 0.9858 | 0.9724 | 23137 | 521.4 | 0.3 |
| BiLSTM | 0.9325 | 0.9702 | 0.8976 | 0.9858 | 0.9662 | 56801 | 1887.6 | 1.998 |
| Transformer | 0.9155 | 0.961 | 0.874 | 0.9817 | 0.9573 | 90017 | 11134.0 | 9.222 |

- BiLSTM vs CNN: ΔF1 -0.0022 [-0.013, 0.0085], p 0.7294 (Holm 0.7294)
- Transformer vs CNN: ΔF1 -0.0192 [-0.0349, -0.0048], p 0.006 (Holm 0.012)
- Harness CNN agrees with the saved CNN@0.5 on 99.5% of files (saved CNN@0.5 F1 0.9342).
