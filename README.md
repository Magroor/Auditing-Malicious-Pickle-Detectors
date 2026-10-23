# Auditing Malicious-Pickle Detectors: code, manifests and per-file verdicts

Code, manifests and per-file verdicts for

> Muhammad Aun, Sajid Majeed, Muhammad Majid Adeel, Nibras Ahmad and M Arslan Saleem Sandila.
> *Auditing Malicious-Pickle Detectors: Benchmark Contamination, External False Positives and a Provably
> Invariant Canonical Form.* Journal of Information Security and Applications, under review.
> Archive DOI: [10.5281/zenodo.23509582](https://doi.org/10.5281/zenodo.23509582) (version 1.0.0).
> All versions: [10.5281/zenodo.23509581](https://doi.org/10.5281/zenodo.23509581). See `CITATION.cff`.

The paper audits static detectors for malicious Python pickles in model files. It measures benchmark
contamination, defines a semantic canonical form of the opcode stream that is provably invariant to inert
insertion (within a declared machine and read caps), and validates the detectors on 166 official
torchvision checkpoints. All analysis is static: no pickle is ever unpickled, imported or executed.

## Quick start

```
pip install -r requirements.txt
python -I reproduce.py --experiment all
python -I reproduce.py --help
```

`reproduce.py` recomputes tables from saved verdicts. Its full output on the released files is in
`expected_output.txt` (SHA-256 of the LF-normalised file: `24e621088568a6ce705302fc2444dc2762a03cd90f1f1a8b33f1168a16821aa5`). Compare with
`python reproduce.py --experiment all > out.txt` and `diff --strip-trailing-cr out.txt expected_output.txt`. Nothing is retrained and nothing is scored. The
`dev`, `locked_test` and `section14` experiments need numpy, scipy, scikit-learn and xgboost to import
(pinned versions are in `requirements.txt`); `external` needs only the standard library. If your packages
live in the user site directory, run without `-I`.

## What is reproduced

| Experiment | Recomputed from | Paper content |
|---|---|---|
| `dev` | `app/experiments_v2/results/fuse/v2/` | First development run: 747 files, repetition 0 of 5x5 grouped CV. F1 per detector, FUSE minus SP-RF (+0.0062, p = 0.61), non-inferiority with Holm correction. Exploratory. |
| `locked_test` | `app/experiments_v2/results/final/` | The single locked-test run on 139 files (manifest `1aaa27a4...`): F1, Wilson intervals, non-inferiority, McNemar. |
| `section14` | `app/experiments_v2/results/fuse/v2/` | Metadata-hard subset and three-way verdict (verified / unverified). |
| `external` | `verdicts/external/` | False alarms of each detector on the 166 official checkpoints with Wilson intervals and the exact McNemar test (FUSE 159/166, SP-RF 136, SP-CB 110). |

## What is not reproduced

- **No model is retrained.** This repository ships the detection and statistics code that `reproduce.py`
  needs, the saved verdicts and the manifests. Training and corpus-building scripts are not included,
  and the saved verdicts are the evidence.
- **Development runs.** `reproduce.py dev` recomputes the first run (FUSE F1 0.9551), the one the adoption
  decision used. The result files of both runs the paper cites are in `verdicts/dev/first_run/` and
  `verdicts/dev/second_run/` (FUSE 0.9739, SP-RF 0.9467). `verdicts/dev/fuse_dev_results.json` is a later
  recomputation on the second run's feature cache, which agrees with the second run to within one SP-RF
  verdict (0.9469).
- **The five-axis adaptive study is reproduced from its released per-variant records, not regenerated.**
  `python -I harness/adaptive_stats.py --records verdicts/adaptive/records.jsonl --out results.json`
  recomputes the adaptive detection-rate and benign-FPR tables exactly (it matches
  `verdicts/adaptive/results.json`). The records hold hashes, axes, budgets and scores only, no file bytes.
  `python -I harness/matched_operating_point.py` recomputes the exploratory matched-operating-point table
  (supplement Table S12) from the same records.
  Generating new variants needs the attack tooling, which is withheld (see Ethics) and available in
  confidence to the editor, reviewers and verified researchers on request.
- **The insertion-invariance pairs on real files** are reported in the paper. Their generator is withheld
  for the same reason.
- **Leave-one-source-out, the architecture comparison and the MalHug cross-source check** are shipped as
  result files but are not recomputed by `reproduce.py`. The leave-one-source-out numbers in the paper
  (recall 0.467 to 0.582 with the curated source held out) are the fold-0 range of the final run,
  `app/experiments_v2/results/final_colab/loso_shift.json` (lowest SP-RF, 0.467). The other stored run,
  `verdicts/shift/loso_shift.json`, gives 0.475 to 0.582 (lowest FUSE-C). FUSE, FUSE-INV, SP-CB and META
  have the same fold-0 recall in both runs.
  The architecture comparison is in `verdicts/arch/` and the MalHug check in
  `verdicts/external/external_malicious.*`.
- **Raw corpora are not shipped**, so re-scoring from bytes needs the downloads below.
- No AUC or threshold sweep exists for the external checkpoints, because raw scores were not saved.
- **Read-cap experiment (16 MiB against 64 MiB)** and the **739-file feature-block ablation** are shipped
  as result files in `app/experiments_v2/results/cap_eval_64/` and `app/experiments_v2/results/ablation_739/`.

`NUMBERS.md` maps each main paper table to its result file.

## Layout

```
reproduce.py                  entry point (adds the code folders to sys.path, then dispatches)
app/picklescan_ml/            feature extraction, rules and the semantic canonicaliser
app/experiments_v2/           FUSE, SafePickle and META evaluation, three-way verdict, statistics
app/experiments_v2/data/      SHA-256 manifests and URL lists (dev reference, PickleBall sealed half, official checkpoints)
app/experiments_v2/results/   saved per-file predictions and run summaries
harness/                      statistics for the adaptive study, recomputed from released records
verdicts/  manifests/  file_meta.json  logs/  protocol/    released result files, seals and the pre-registration
```

## Data sources

- Training and evaluation corpus: the public Hugging Face datasets `HFscanner1231/pickle-curated`,
  `HFscanner1231/pickle-malwares` and `HFscanner1231/pickle-picklecloak`, fetched from Hugging Face with
  your own account. Check files against `manifests/locked_test_manifest.json`,
  `app/experiments_v2/data/dev_reference.json` and `app/experiments_v2/data/pickleball_sealed_shas.json`.
- External benign checkpoints: the 166 official torchvision weights (14 quantized) listed in
  `app/experiments_v2/data/official_benign_torchvision.json`, all from `download.pytorch.org`. The list
  hash is in `manifests/external_official_166_done.json`.
- External malicious files: the MalHug collection (Zenodo record 13850049); the seal is
  `manifests/external_malicious_seal.json`.

Library versions of the original runs are in `manifests/run_info.json`.

## Ethics

This is a defensive measurement study. The repository contains no malware bytes, no pickle files, no model
checkpoints and no constructed evasion samples. Corpora are referenced by public identifiers and SHA-256
manifests only. The attack and adaptive-evasion tooling used in the paper (variant generators, search
attacks, evasion driver notebooks) is cited but deliberately **not released**, because publishing it would
hand ready-made evasion mechanics to attackers. The training and corpus-building scripts, which share
modules with that tooling, are withheld as well. All of it is available in confidence to the editor,
reviewers and verified researchers on request. Code paths that would need withheld modules, such as
`fuse_eval.py --attack`, raise `ImportError`, and every table that `reproduce.py` recomputes is unaffected.

## Licence

MIT, see `LICENSE`. Third-party datasets and checkpoints keep their own licences.
