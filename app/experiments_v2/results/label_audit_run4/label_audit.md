# Label audit (rule-based) and its effect on the dev comparisons

Results folder: `v2_results (4)/v2`; locked manifest `1aaa27a4` (asserted). META source: {'0': 'recomputed (meta_baseline.fit_meta, identical folds)', '1': 'recomputed (meta_baseline.fit_meta, identical folds)', '2': 'recomputed (meta_baseline.fit_meta, identical folds)', '3': 'recomputed (meta_baseline.fit_meta, identical folds)', '4': 'recomputed (meta_baseline.fit_meta, identical folds)'}. Exploratory; static fields only.

## Rules

| id | name | strength | statement |
|---|---|---|---|
| M1 | empty_file | definite | malicious label, 0 bytes |
| M2 | no_effect_no_import | definite | malicious label, stream verified, semantic analysis finds no live effect, no call, no static or dynamic import and no persistent id (cannot execute anything when loaded) |
| M3 | same_group_as_benign | strong | malicious label, verified, and its pre-registered near-duplicate group (identical canonical opcode-name sequence and identical imported globals) contains a dev benign file |
| M4 | benign_static_twin | strong | malicious label, verified, no non-allowlisted and no dynamic import, and static profile (container, proto, n_pkl_members, n_streams, parse_error, byte_tokens, n_nonallowlisted, picklescan_dangerous, sem_n_members, sem_broken, sem_n_dynamic_imports, sem_n_nonallow_imports, sem_n_persid, nonallow_beyond_window) identical to at least one dev benign file |
| M5 | name_says_not_malicious | weak | malicious label and file name matches /not[ _-]*mal/i |
| B1 | conflicting_label_sha | definite | the same SHA-256 appears with both labels (dropped by stage 2; disclosure only) |
| B2 | tiny_flagged_benign | weak | benign label, verified, bare pickle of at most 4096 bytes, picklescan reports a dangerous global |

## Suspects

| membership | label | origin | path tail | bytes | rules | sha256 |
|---|---|---|---|---|---|---|
| dev | 0 | pickle-curated | 0413_file1.pkl | 94 | B2 | 2f88aac24b25f7ac |
| dev | 1 | pickle-curated | tchtower_sample_files__sample_model_files__sample_pickle.pkl | 0 | M1 | e3b0c44298fc1c14 |
| dev | 1 | pickle-curated | 0059_training_args.bin | 4091 | M4 | c4fd602b884c18f1 |
| dev | 1 | pickle-curated | 0160_coldwaterq__sectest__sectest__testtest.pt | 145 | M2 | 6b03489ef8586a2b |
| dev | 1 | pickle-curated | 0220_training_args.bin | 5304 | M3,M4 | 5536fd2dd1ec3317 |
| dev | 1 | pickle-curated | 0283_training_args.bin | 4027 | M3,M4 | d00702edde9fc3ef |
| dev | 1 | pickle-curated | 0316_training_args.bin | 5688 | M3,M4 | 01d76d0cc8179b82 |
| dev | 1 | pickle-curated | 0366_coldwaterq__sectest__sectest__test.pt | 29 | M2 | 43561882d4a6730d |
| dev | 1 | pickle-curated | 0416_training_args.bin | 4539 | M4 | 202a5542d25d5172 |
| dev | 1 | pickle-curated | 0648_training_args.bin | 4536 | M3,M4 | dea37d5e3dca8c9f |
| dev | 1 | pickle-curated | 0753_coldwaterq__sectest__data.pkl | 12 | M2 | 8efd62e5d0cc5ae5 |
| dev | 1 | pickle-curated | 0828_moom825__testing__testing__not mal.pkl | 127 | M5 | 7bdec29a9d287a13 |
| locked | - | - | - | - | M4 | 591d5e3807bf1a1a |
| locked | - | - | - | - | M4 | 5c3ab9b1d7a8f514 |
| locked | - | - | - | - | M4 | 429eab03ec63e27f |
| dropped (6 copies, labels [0, 1]) | - | pickle-curated | 0106_tokenize_fn.pkl; 0349_tokenize_fn.pkl; 0352_tokenize_fn.pkl; 0636_tokenize_fn.pkl; 06 | - | B1 | 46f96ac7225a9156 |
| dropped (2 copies, labels [0, 1]) | - | pickle-curated | 0622_graniet__twgewgwe__twgewgwe__Baddream.pkl; 0723_Baddream.pkl | - | B1 | 5183d42aa7a0d9ba |
| dropped (5 copies, labels [0, 1]) | - | pickle-curated | 0530_data.pkl; 0589_data.pkl; 0870_drhyrum__bert_tiny_torch_vuln__data.pkl; bert_model_uns | - | B1 | c8354611d7d2f243 |

Counts: {'dev': 12, 'dev_malicious': 11, 'dev_benign': 1, 'locked': 3, 'conflicting_sha': 3, 'by_rule': {'M1': 1, 'M2': 3, 'M3': 4, 'M4': 9, 'M5': 1, 'B2': 1}}

## Repetition 0: F1 (TP/FP) and paired dF1 vs SP-RF [95 % CI, file-level bootstrap]

| model | all_dev (n removed 0) | excl_definite_strong (n removed 10) | excl_all_suspects (n removed 12) |
|---|---|---|---|
| ML | 0.9405 (229/4); -0.0063 [-0.0216, 0.0088] | 0.9602 (229/4); +0.0002 [-0.013, 0.0134] | 0.9642 (229/3); +0.0002 [-0.013, 0.0134] |
| CNN | 0.9298 (225/5); -0.0170 [-0.0357, 0.0017] | 0.9494 (225/5); -0.0106 [-0.0283, 0.0066] | 0.9534 (225/4); -0.0107 [-0.0283, 0.0067] |
| CNN@0.5 | 0.9328 (229/8); -0.0139 [-0.0317, 0.0031] | 0.9522 (229/8); -0.0078 [-0.0244, 0.0088] | 0.9562 (229/7); -0.0079 [-0.0248, 0.0088] |
| SP-RF | 0.9467 (231/3) | 0.9600 (228/3) | 0.9641 (228/2) |
| SP-CB | 0.9467 (231/3); +0.0000 [0.0, 0.0] | 0.9600 (228/3); +0.0000 [0.0, 0.0] | 0.9641 (228/2); +0.0000 [0.0, 0.0] |
| SP-RF-tuned | 0.9244 (220/2); -0.0224 [-0.0383, -0.009] | 0.9397 (218/2); -0.0203 [-0.0358, -0.007] | 0.9437 (218/1); -0.0203 [-0.0361, -0.0069] |
| META | 0.9520 (238/8); +0.0053 [-0.0154, 0.0265] | 0.9630 (234/8); +0.0030 [-0.0175, 0.0242] | 0.9648 (233/7); +0.0007 [-0.02, 0.0219] |

## Mean over repetitions: F1 and dF1 vs SP-RF

| model | all_dev | excl_definite_strong | excl_all_suspects |
|---|---|---|---|
| ML | 0.9347 (-0.0065) | 0.9543 (-0.0004) | 0.9583 (-0.0004) |
| CNN | 0.9326 (-0.0086) | 0.9522 (-0.0026) | 0.9562 (-0.0026) |
| CNN@0.5 | 0.9321 (-0.0091) | 0.9514 (-0.0033) | 0.9554 (-0.0033) |
| SP-RF | 0.9413 | 0.9548 | 0.9588 |
| SP-CB | 0.9447 (+0.0035) | 0.9580 (+0.0032) | 0.9620 (+0.0032) |
| SP-RF-tuned | 0.9363 (-0.0049) | 0.9503 (-0.0045) | 0.9543 (-0.0045) |
| META | 0.9502 (+0.0090) | 0.9612 (+0.0064) | 0.9630 (+0.0042) |
