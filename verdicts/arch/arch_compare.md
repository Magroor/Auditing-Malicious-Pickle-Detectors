# Architecture comparison (PREREGISTRATION 12.1, exploratory)

| Encoder | F1 | Precision | Recall | Specificity | AUC | Params | Train s (5 folds) | CPU ms/file |
|---|---|---|---|---|---|---|---|---|
| CNN | 0.9344 | 0.9744 | 0.8976 | 0.9878 | 0.9703 | 23137 | 46.2 | 0.378 |
| BiLSTM | 0.9371 | 0.9665 | 0.9094 | 0.9838 | 0.9733 | 56801 | 48.5 | 0.734 |
| Transformer | 0.9309 | 0.9622 | 0.9016 | 0.9817 | 0.9663 | 90017 | 116.5 | 9.413 |

- BiLSTM vs CNN: ΔF1 0.0027 [-0.0098, 0.0156], p 0.667 (Holm 1.0)
- Transformer vs CNN: ΔF1 -0.0035 [-0.0178, 0.0108], p 0.6598 (Holm 1.0)
- Harness CNN agrees with the saved CNN@0.5 on 99.5% of files (saved CNN@0.5 F1 0.938).
