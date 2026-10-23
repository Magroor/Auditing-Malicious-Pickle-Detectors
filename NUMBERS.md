# NUMBERS.md: paper tables and the files behind them

This is a stub. Check every row against the final manuscript before release.

| Paper table / claim | Result file(s) | Recompute with |
|---|---|---|
| Real-corpus results, top: first development run (747 files) | `app/experiments_v2/results/fuse/v2/{file_meta,fuse_cv_rep0}.json` | `python -I reproduce.py --experiment dev` |
| Second development run (FUSE F1 0.9739) | `verdicts/dev/fuse_dev_results.json`, `verdicts/dev/fuse_cv_rep*.json` | stored summary only |
| Real-corpus results, middle: locked test (139 files) | `app/experiments_v2/results/final/final_locked_results.json`, `manifests/locked_test_manifest.json` | `--experiment locked_test` |
| Metadata-hard subset, three-way verdict | `app/experiments_v2/results/fuse/v2/` | `--experiment section14` |
| External-checkpoint validation (166 checkpoints) | `verdicts/external/external_official_benign.{json,md}` | `--experiment external` |
| MalHug cross-source check (16 scored, 2 novel) | `verdicts/external/external_malicious.{json,md}`, `manifests/external_malicious_seal.json` | stored only |
| Leave-one-source-out shift | `app/experiments_v2/results/final_colab/loso_shift.{json,md}` and `verdicts/shift/loso_shift.json` (two stored runs; SP-RF 0.467 and 0.508) | stored only |
| Architecture comparison | `verdicts/arch/arch_compare.{json,md}` | stored only |
| Cap audit, cluster bootstrap, label audit, stratified re-analysis | `app/experiments_v2/results/{cap_audit_run4,cluster_bootstrap_run4,label_audit_run4,stratified_reanalysis_run4}/` | the script of the same name in `app/experiments_v2/` |
| Sealed PickleBall half | `app/experiments_v2/results/final_colab/pickleball_*_sealed*.json` | stored only |
| Invariance on 1,391 inert pairs and the five-axis adaptive table | not released (withheld attack tooling) | not reproducible from this repository |
