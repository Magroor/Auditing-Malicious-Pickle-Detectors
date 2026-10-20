# COLAB_FINAL results (PREREGISTRATION 12; received 2026-10-05, bundle `1d0b8525`)

Static analysis only; JSON read, nothing unpickled. The locked set was not scored in this notebook.

## 12.1 Architecture comparison (dev, repetition-0 folds, seed 0, threshold 0.5; exploratory)

| Encoder | F1 | Precision | Recall | Specificity | AUC | Params | Train s (5 folds) | CPU ms/file |
|---|---|---|---|---|---|---|---|---|
| CNN | 0.9347 | 0.9703 | 0.9016 | 0.9858 | 0.9724 | 23137 | 521.4 | 0.3 |
| BiLSTM | 0.9325 | 0.9702 | 0.8976 | 0.9858 | 0.9662 | 56801 | 1887.6 | 1.998 |
| Transformer | 0.9155 | 0.961 | 0.874 | 0.9817 | 0.9573 | 90017 | 11134.0 | 9.222 |

- BiLSTM vs CNN: ΔF1 -0.0022 [-0.013, 0.0085], p 0.7294 (Holm 0.7294)
- Transformer vs CNN: ΔF1 -0.0192 [-0.0349, -0.0048], p 0.006 (Holm 0.012)
- Harness CNN agrees with the saved CNN@0.5 on 99.5% of files (saved CNN@0.5 F1 0.9342).

Reading: the CNN is as accurate as a BiLSTM (ΔF1 −0.002, p 0.73) and significantly better than a Transformer (−0.019, Holm p 0.012), with 2.4× fewer parameters than the BiLSTM, 3.6× faster training and 6.7× faster CPU inference. The harness CNN reproduces the saved CNN@0.5 on 99.5% of files.

## 12.2 Leave-one-source-out shift test (exploratory)

## Held-out malicious source: pickle-curated

| Detector | Recall (fold-0 model) | Wilson 95% | Range over 5 models | In-distribution recall | FA rate | Wilson 95% |
|---|---|---|---|---|---|---|
| FUSE | 0.5082 (n=122) | [0.4206, 0.5953] | [0.5082, 0.623] | 0.8361 | 0.002 (1/493) | [0.0004, 0.0114] |
| FUSE-C | 0.4754 (n=122) | [0.3889, 0.5634] | [0.4754, 0.6066] | 0.7951 | 0.0041 (2/493) | [0.0011, 0.0147] |
| FUSE-INV | 0.582 (n=122) | [0.4933, 0.6657] | [0.582, 0.582] | 0.8525 | 0.0061 (3/493) | [0.0021, 0.0177] |
| SP-RF | 0.4672 (n=122) | [0.381, 0.5554] | [0.4508, 0.5656] | 0.8852 | 0.002 (1/493) | [0.0004, 0.0114] |
| SP-CB | 0.4918 (n=122) | [0.4047, 0.5794] | [0.4918, 0.5902] | 0.877 | 0.002 (1/493) | [0.0004, 0.0114] |
| META | 0.582 (n=122) | [0.4933, 0.6657] | [0.582, 0.623] | 0.8689 | 0.002 (1/493) | [0.0004, 0.0114] |
| ML | 0.5164 (n=122) | [0.4286, 0.6032] | [0.4426, 0.5574] | 0.8443 | 0.002 (1/493) | [0.0004, 0.0114] |

## Held-out malicious source: pickle-picklecloak

| Detector | Recall (fold-0 model) | Wilson 95% | Range over 5 models | In-distribution recall | FA rate | Wilson 95% |
|---|---|---|---|---|---|---|
| FUSE | 1.0 (n=127) | [0.9706, 1.0] | [1.0, 1.0] | 1.0 | 0.0122 (6/493) | [0.0056, 0.0263] |
| FUSE-C | 0.9449 (n=127) | [0.8906, 0.973] | [0.9449, 0.9449] | 0.9528 | 0.0122 (6/493) | [0.0056, 0.0263] |
| FUSE-INV | 0.8976 (n=127) | [0.8327, 0.9392] | [0.8976, 0.9449] | 0.9449 | 0.0122 (6/493) | [0.0056, 0.0263] |
| SP-RF | 0.9449 (n=127) | [0.8906, 0.973] | [0.9449, 0.9449] | 0.9449 | 0.0142 (7/493) | [0.0069, 0.029] |
| SP-CB | 0.9449 (n=127) | [0.8906, 0.973] | [0.9449, 0.9449] | 0.9449 | 0.0081 (4/493) | [0.0032, 0.0207] |
| META | 1.0 (n=127) | [0.9706, 1.0] | [1.0, 1.0] | 1.0 | 0.0183 (9/493) | [0.0096, 0.0343] |
| ML | 0.8583 (n=127) | [0.7871, 0.9084] | [0.7559, 0.8819] | 0.9606 | 0.0122 (6/493) | [0.0056, 0.0263] |

Reading: when every curated malicious file is removed from training, recall on them falls from 0.80–0.89 to 0.47–0.58 for every detector (FUSE 0.508, SP-RF 0.467, META and FUSE-INV 0.582), at a false-alarm rate of at most 0.6%. Holding out the PickleCloak source barely hurts (FUSE and META 1.000, SafePickle 0.945). No detector generalises to an unseen malicious source; this is the shift result reviewers asked for.

## 12.3 PickleBall sealed half (final run, part 2; scored once; manifest `990c452f` matches)

After de-duplication against our corpus and the content/80 MB filter: **2 malicious and 4 benign files**. Descriptive only; no rate is estimable.

| Detector | Malicious caught | Benign false alarms |
|---|---|---|
| ML@tuned | 1/2 | 0/4 |
| ML@0.5 | 1/2 | 2/4 |
| CNN@tuned | 2/2 | 1/4 |
| CNN@0.5 | 2/2 | 1/4 |
| SP-style@tuned | 2/2 | 2/4 |
| SP-RF@0.5 | 2/2 | 0/4 |
| SP-CB@0.5 | 2/2 | 2/4 |
| SP-AE@p95 | 2/2 | 4/4 |
| META@0.5 | 2/2 | 2/4 |
| CNNv2@tuned | 2/2 | 1/4 |
| CNNv2@0.5 | 2/2 | 1/4 |
| FUSE@0.5 | 2/2 | 0/4 |
| FUSE-C@0.5 | 2/2 | 0/4 |
| FUSE-INV@0.5 | 2/2 | 2/4 |

FUSE, FUSE-C and SP-RF catch both malicious files with no false alarm; the set is too small to rank anything. Together with the explore half (F-90), PickleBall gives no usable external estimate because it overlaps the SafePickle corpus.
