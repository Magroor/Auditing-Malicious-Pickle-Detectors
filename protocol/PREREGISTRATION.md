# Pre-registered analysis plan, robustness v2

Fixed on 2026-10-02, BEFORE any v2 result, any de-duplicated real-corpus result or any
per-file real-corpus prediction exists. Changes after this date are listed in the
amendment log at the end with their date and reason. Results that come from a changed
analysis are labelled exploratory in the paper.

## 1. Why the old test is replaced

The v1 paper compared detectors with a two-sided sign test over 5 folds. Its smallest
possible p-value is 2 x 0.5^5 = 0.0625, reached only when one model wins all five folds,
so it can never reach 0.05. It is kept only as a descriptive count of fold wins.

## 2. Data

1. Corpus: the public SafePickle corpus, Hugging Face datasets `HFscanner1231/pickle-malwares`,
   `pickle-picklecloak`, `pickle-curated`, selected exactly as in the v1 1008-file run, which was
   `app/COLAB_CELL.py`: every file under a benign/ or malicious/ folder of at most 80 MB
   (reproduced in `v2_download.py`). The file count and a hash of the file list are recorded and
   compared with the v1 counts (1008 = 590 benign + 418 malicious).
2. Exact de-duplication: SHA-256 of the raw file bytes. One copy per hash is kept. A hash
   that appears with both labels is dropped entirely and the count is reported.
3. Near-duplicate grouping: group id = SHA-256 of (canonicalised opcode-name sequence of the
   inner stream, sorted set of imported globals). Files with a parse error or zero opcodes get
   their own raw-SHA-256 group, so broken files are not lumped together. All folds and splits
   below keep a group on one side.
4. Locked test set: 25 % of the groups, stratified by label, `StratifiedGroupKFold(n_splits=4,
   shuffle=True, random_state=20261002)`, first fold. Its SHA-256 list is written to
   `locked_test_manifest.json` with a hash of that file recorded in the run log. No model,
   feature, threshold or design decision may use it until the final run in section 6.
   The remaining 75 % is the development set.
5. The synthetic training set (`train_deep.augmented_training()`, 1206 files) is added to every
   training fold of OUR models, as in v1. It never enters a test fold.

## 3. Detectors

| ID | Detector | Threshold |
|---|---|---|
| ML | v1 RF + ExtraTrees + XGB ensemble on the 96 v1 features (`safepickle_train_eval._fit_ensemble`) | inner 3-fold CV on the training fold, grid 0.25..0.75, max F1 (as v1) |
| CNN | v1 fused OpcodeCNN, seed = repetition index | primary: inner 3-fold CV as for ML. Also reported: fixed 0.5 (as v1) |
| CNNv2 | v2 detector: 1D CNN over the semantic canonical stream + monotone non-negative evidence head + opcode-frequency branch (`picklescan_ml/deep_v2.py`), trained on the hardened synthetic set (`augmented_training_hardened`), seed = repetition index | primary: inner 3-fold CV as for CNN. Also reported: fixed 0.5 |
| SP-RF | SafePickle, faithful: opcode frequency vector f_i = count_i / sum_j count_j from `pickletools.genops` of the inner `data.pkl` (no canonicalisation), all-zero columns of the training fold dropped, `RandomForestClassifier()` with sklearn defaults, trained on the real training fold only | 0.5 (paper uses defaults and states no threshold rule) |
| SP-CB | same features, `CatBoostClassifier(verbose=0)` defaults | 0.5 |
| SP-AE | same features, autoencoder trained on benign training files only (our choice, the paper gives no architecture): d -> 32 -> 8 -> 32 -> d, ReLU, MSE, Adam 1e-3, 100 epochs, batch 32 | 95th percentile of benign training reconstruction error |
| SP-style | v1 "SafePickle-style" baseline (raw counts, RF + GB) for continuity with the v1 paper | inner CV as v1 |

SP-RF is the primary SafePickle comparator because the SafePickle paper names RandomForest
as its strongest model. A sensitivity analysis repeats SP-RF with the inner-CV threshold and
with the synthetic set added to its training data.

## 4. Statistical tests

Unit of analysis: the file. Every model writes one out-of-fold prediction and probability per file.

Primary comparisons (family of three, Holm correction, family-wise alpha 0.05):
- P1: ML vs SP-RF on F1.
- P2: CNN (inner-CV threshold) vs SP-RF on F1.
- P3: CNNv2 (inner-CV threshold) vs SP-RF on F1. Added 2026-10-02 (see amendment log);
  exploratory until the section 6 locked-test final run.

Primary test: paired stratified bootstrap of the F1 difference over files, 10,000 resamples,
resampling benign and malicious files separately so class sizes stay fixed, seed 0. Report the
95 % percentile CI and the two-sided bootstrap p = 2 x min(share of resamples with delta <= 0,
share with delta >= 0).

Supporting tests, reported for every pair, not used for the primary claim:
- exact McNemar (binomial) on per-file correctness, all files;
- exact McNemar restricted to benign files (specificity) and to malicious files (recall);
- repeated grouped CV: 5 repetitions x 5 folds, Nadeau-Bengio corrected resampled t-test on
  the 25 paired fold F1 differences, with n_test / n_train taken from the actual folds;
- AUC with a paired bootstrap CI;
- fold wins, descriptive only.

## 5. Where each comparison is run

- v1 detectors and all SafePickle variants are frozen. Their confirmatory comparison (P1, P2)
  runs on the pooled out-of-fold predictions of repetition 0 over the development set.
  Repetitions 1-4 feed the corrected t-test.
- Disclosure kept in the paper: the v1 allowlist and token list were widened after zero-shot
  errors on this corpus before this plan existed, so P1 and P2 stay somewhat optimistic for
  ML and CNN.
- v2 is developed on the development set only. Error analysis uses development-set
  out-of-fold predictions only.

## 6. v2 adoption rule and the final run

v2 replaces v1 in the paper only if, on the development set (5 x 5 grouped CV):
1. mean F1 of v2 >= mean F1 of v1 (same detector family), and
2. mean specificity of v2 is not lower than v1 by more than 0.005, and
3. on the white-box attacks of section 7, v2 is at least as robust as v1 on every attack.

The decision is written into the amendment log BEFORE the final run.
Final run, executed once: every frozen detector (ML, CNN, adopted v2, SP-RF, SP-CB, SP-AE,
SP-style) is trained on the whole development set and predicts the locked test set and any
fresh external set (Hide-and-Seek, PickleBall or nullifAI originals, if public). The same
tests as section 4 are applied. All outcomes are reported, favourable or not.

## 7. Robustness evaluation (synthetic attacks, laptop)

- Every neural result is reported as mean +- sample sd over seeds 0-4.
- Attacks on v1 and v2: cancellable pad sweep (canonicaliser off and on), 100-query white-box
  search (protocol re-encoding + pads), non-cancellable pad worst case on direct payloads and
  on gadgets, rename ladder, nullifAI 16.
- If v2 is trained on attack-augmented data, at least one attack family is held out of
  training and reported separately: the non-cancellable APPEND pad and protocols 4-5 are
  held out, training uses only cancellable pads and protocols 0-3.
- A new white-box search is run against v2 itself, with the same 100-query budget, before
  any robustness claim about v2.

## 8. Error analysis variables (development set only)

Per file: label, each model's prediction and probability, container type (zip / raw pickle /
other), number of `.pkl` members in a zip, inner stream bytes, bytes after the first STOP,
number of pickle streams found by sequential parsing, protocol, raw and canonical opcode count,
parse error, opcode index of the first non-allowlisted global in the canonical stream and
whether it is >= 256, byte tokens present, number of non-allowlisted globals, picklescan
dangerous count. Missed malicious files are tabulated by these variables. No file content
beyond these static summaries is printed.

## 9. Additions of 2026-10-03 (after the development results, before any locked or external result)

Everything in this section was added AFTER the step-3 development results were seen (SafePickle
numerically ahead, P1/P2 not significant) and BEFORE the locked test or any external set was
opened. The paper labels it that way.

9.1 Non-inferiority (new primary claim for the final run). For each of our detectors D against
SP-RF and against SP-CB: D is non-inferior if the lower bound of the one-sided 95 % paired
stratified bootstrap interval of F1(D) - F1(SafePickle) is above -0.02 (10,000 resamples, seed 0,
same resampling as section 4). The same rule with margin -0.005 is applied to specificity. Holm
correction over the family {our final detector vs SP-RF, vs SP-CB}. Superiority tests of section 4
are still reported.

9.2 Certified detection rate. For a detector with an insertion guarantee: the share of malicious
files that are detected AND whose canonical stream parses without hitting a cap (stats["broken"]
false), so the theorems of PROOFS.md apply. Detectors without a proof have a certified rate of 0
by definition and are reported with their empirical rate under attack instead.

9.3 CNNv2 and the locked test. CNNv2 was tuned on head-to-head runs over all 888 unique files,
which include the 139 locked-test files. The 2026-10-02 amendment's sentence "v2 is developed on
the dev folds only" was therefore not followed. Consequences, fixed now:
  - the locked test stays confirmatory for v1 ML, v1 CNN, every SafePickle variant and the rule
    scanners, which are frozen and never saw it;
  - for CNNv2 and every later v2 detector (C2) the locked-test result is reported as exploratory;
    their confirmatory evaluation is the external sets (PickleBall, fresh benign Hub models);
  - from 2026-10-03 every v2 design decision uses the 747 development files only.

9.4 Gate G1 outcome. Only 1 of 27 CNN misses has its first non-allowlisted import beyond opcode
256 and none comes from an extra archive member. The "read every statement" rationale for v2 is
withdrawn. v2 is motivated by robustness (insertion guarantee), not by recall.

9.5 In-the-wild scan. The frozen final detector scans fresh pickle checkpoints from the Hugging
Face Hub (statically, `data.pkl` only, in Colab). Every flag is verified by static inspection of
its canonical statements. Counts of flags, verified malicious, false alarms and disclosures are
reported. This is descriptive and outside the hypothesis tests.

## 10. Additions of 2026-10-04 (after a code and results audit, BEFORE any external, attack or locked result)

Everything here was written after the audit recorded in `EXECUTION_PLAN.md` (corrections log),
`STRENGTHS_WEAKNESSES_PLAN.md` and `FAILURE_LOG.md`, and before the first PickleBall explore run,
the first real-file attack study, the cap re-scan and the final run. The paper labels it that way.

10.1 Read caps and the fail-closed policy. A file is *unverified* when the static reader did not
finish it: `byte_cap` (inner stream > 16 MiB; the v1, SafePickle and semantic readers then read
nothing), `op_cap` (10^6 opcodes reached) or `malformed` (any other parse failure), as computed by
`meta_baseline.cap_reason`. Every results table reports each detector as built AND as `+FC`
(unverified => flagged). Disclosed: no detector evaluated so far is fail-closed; in run 4 all 35
over-cap dev files (33 benign, 2 malicious) were scored benign by CNN, ML and SP-RF.

10.2 Scope of the guarantees. PROOFS.md theorems hold under assumption A3 (within the caps); an
insertion can itself break A3 (about 10^6 cancellable opcodes). The certified detection rate of 9.2
is redefined: the share of malicious files that are detected AND verified clean, for a detector that
is monotone under insertion while verified AND flags every unverified file. A detector that is not
fail-closed is reported with an explicit budget (10^6 opcodes / 16 MiB). CNNv2 has no certificate:
its raw-byte token gate loses tokens under an inert insertion (NONE, POP after a string argument;
counterexample in FAILURE_LOG F-02). C2 takes token evidence only from parsed atoms.

10.3 PickleBall split. Unit = tar member path minus the file name. Half =
('explore','sealed')[int(sha256("NED-pickleball-split-v1:" + unit).hexdigest(), 16) & 1]; the salt is
fixed and never changed after the first full explore run. Explore runs score only the explore half
and write a SHA-256 manifest of the sealed half (never featurised). The sealed half is the
confirmatory external set for every detector (incl. CNNv2 and C2); it is opened once, in the final
run (`--half sealed --final-run --with-cnnv2`, manifest hash checked). Members are selected by
content (pickle stream or zip with a .pkl member); object `.npy` files are out of scope and counted.
Primary metrics: recall and false-alarm rate with Wilson 95 % intervals, at file AND unit level;
F1 secondary. With about 84 malicious files the -0.02 non-inferiority margin is not testable on
PickleBall (power_analysis.md): it is reported as estimation with intervals, not as a test.
SafePickle's published PickleBall figure is context only (different training data and subset; its
attribution is to be verified against the SafePickle paper before it is cited).

10.4 META and `+FC` rows are mandatory in every table, including external, attack and protocol tables.

10.5 G-C (protocol re-encoding) is a mechanism demonstration: its pass criterion holds by
construction and it uses synthetic objects only. It does not count towards the framing decision.

10.6 Head-to-head universe. `colab_headtohead.py` kept the first copy of every SHA, so the 3
conflicting-label hashes (13 files) entered as benign, and it skipped the 0-byte file (888 files vs
886). All head-to-head numbers so far carry this and stay exploratory. Before any further
head-to-head run the script applies the stage-2 rule (conflicting hashes dropped) and each fold's
own threshold.

10.7 Real-file attack study (`attack_study_real.py`). Out-of-fold (an attacked file is never in its
detectors' training folds), existing families A1/A1b/A3/A9 only, origin-stratified seeded sampling,
reported per family and position, with META and `+FC` rows. Exploratory.

## 11. Additions of 2026-10-05 (fused detector FUSE; BEFORE any FUSE result and before the final run)

Written after every development, attack and PickleBall-explore result listed in the amendment log, and
before any FUSE number exists. FUSE was designed from those development results, so its development
CV is exploratory. Its confirmatory evaluation is the single final run on the locked test (section 6)
and the sealed PickleBall half. FUSE never saw the locked 139 files: every design decision below uses
the 747 development files only, so section 9.3's contamination does not apply to it.

11.1 Detectors (code: `fuse_eval.py`, frozen at the commit that adds this section). All trained on
real training-fold files only (no synthetic set), threshold fixed at 0.5, no tuning. Model of each:
the mean probability of RandomForest(n_estimators=500, sklearn defaults otherwise, random_state = rep)
and HistGradientBoostingClassifier(defaults, random_state = rep).
- **FUSE** (primary): SafePickle opcode frequency + semantic canonical opcode frequency + the 13
  semantic stats (log1p) + the META vector + the v1 scalars.
- **FUSE-INV** (primary, robustness): semantic canonical opcode frequency + the six stats read from the
  canonical graph's live part or the archive layout (n_members, n_effects, n_calls, n_static_imports,
  n_nonallow_imports, n_emitted). Every feature is a function of the canonical form, so by Theorem 1
  its score cannot change under an inert insertion that stays within the read caps (checked by
  `tests/test_fuse_eval.py`). It has no guarantee for live insertions (A3) or protocol re-encoding
  outside Theorem 2's declared scope.
- **FUSE-C** (secondary): content only, SafePickle frequency + semantic frequency + semantic stats. It
  measures how much of FUSE comes from metadata.
Each is also reported `+FC` (section 10.1).

11.2 Development analysis (exploratory). The 5 x 5 grouped CV on the same folds as stage 3, with
SP-RF, SP-CB and META re-fitted on the identical folds so every comparison is paired. Reported: the
section 4 statistics, non-inferiority (9.1) of FUSE and FUSE-INV against SP-RF and SP-CB, superiority
against SP-RF (bootstrap, Holm over the three FUSE detectors), comparison with META, results by
container.

11.3 Attack study (exploratory, section 10.7 harness unchanged except F-91's fix). Seeds 0 and 1,
40 sampled malicious dev files each, existing families A1/A1b/A3/A9 only, FUSE rows added.

11.4 Adoption rule, fixed now. A FUSE detector enters the final run as "our detector" only if, on the
development set: (a) it is non-inferior to SP-RF and to SP-CB at margin -0.02 F1 after Holm (9.1);
(b) its specificity is not lower than SP-RF's by more than 0.005; (c) in both attack seeds its number
of evaded files is no larger than SP-RF's. If FUSE and FUSE-INV both pass, both enter; the paper's
robustness claim then rests on FUSE-INV, and its accuracy claim on whichever is reported in the final
run with Holm over the two. If neither passes, the final run still reports them (all outcomes are
reported) and the paper does not call any of our detectors robust. The decision is written into the
amendment log before the final run.

11.5 What "robust" may mean in the paper. Only: (i) non-inferior clean F1 on the locked test, (ii) no
evaded file in the measured attack families in both seeds, (iii) the invariance proof for inert
insertion within the caps, and (iv) the fail-closed policy for unverified streams with its measured
cost. Adaptive attacks that are not in A1/A1b/A3/A9 are outside the claim and are named as such.

## 12. Additions of 2026-10-05 (reviewer-driven development analyses; BEFORE their results and before the final run)

Written after the FUSE decision (amendment log) and after external reviews of the first manuscript, before
any result of the analyses below exists. Both are exploratory development analyses on the 747 dev files;
neither touches the locked set or the PickleBall sealed half. Code: `extras_eval.py`.

12.1 Architecture comparison (reviewer request: justify the 1D CNN against LSTM and Transformer). Three
sequence encoders share one harness: the same 256-opcode input, the same embedding (32), the same fused v1
scalars, the same head, loss (BCE with class weight), optimiser (Adam 1e-3, weight decay 1e-4), batch 32,
40 epochs, training data (synthetic set + real training fold, as the v1 CNN) and threshold 0.5. Encoders:
CNN (the v1 two-kernel convolution, re-trained in this harness), BiLSTM (hidden 64 per direction, max
pooling over time) and Transformer (2 encoder layers, d_model 64, 4 heads, feed-forward 128, learned
positions, max pooling). Folds: the five folds of repetition 0 (stage 3), seed 0. Reported: F1, precision,
recall, specificity, AUC, parameter count, training seconds and CPU milliseconds per file; paired
bootstrap ΔF1 (section 4 method) of BiLSTM and Transformer against the harness CNN, Holm over the two.

12.2 Leave-one-source-out shift test (reviewer request: temporal / TESSERACT-style split; the corpus has
no reliable dates, so the shift axis is the malicious source). For each held-out malicious source S in
{pickle-curated, pickle-picklecloak}: the test set is every dev malicious file of S plus one grouped fifth
of the dev benign files (StratifiedGroupKFold over the benign groups, 5 folds, seed 0, so every benign
file is tested once); training is the remaining dev files with every malicious file of S removed and
every training file whose structural group appears in the test set removed. pickle-malwares (5 files)
always stays in training and is not held out. Detectors: FUSE, FUSE-INV, FUSE-C, SP-RF, SP-CB, META and
the ML ensemble (fixed thresholds 0.5; ML uses its inner-CV threshold), trained as in `fuse_eval.dev_cv`
and `colab_v2_eval.run_fold`. Reported per S and detector: recall on S with a Wilson 95 % interval,
false-alarm rate on the benign test files with a Wilson interval, and the in-distribution recall of the
same detector on S from the repetition-0 CV for contrast.

12.3 The final run (section 6, decision of 2026-10-05) also scores FUSE, FUSE-C and FUSE-INV on the
PickleBall sealed half (`pickleball_eval.py --half sealed --final-run --with-cnnv2 --with-fuse`).

## 13. Additions of 2026-10-06 (external malicious source; BEFORE any such file is received)

Written after the final run and before any file of an external malicious source has been requested,
received or featurised. Reason: leave-one-source-out recall (12.2) falls to about 0.5 for every detector,
so the open question is behaviour on a malicious source that is absent from the SafePickle corpus.

13.1 Source. Malicious (and, if offered, benign) pickle model files obtained from the authors of a
published study (for example MalHug, ASE 2024), on their terms. No Hugging Face Hub harvesting. Files are
handled statically only (pickletools / zipfile reads); nothing is ever unpickled, loaded or executed, and
no sample byte is redistributed. Only aggregate results and a SHA-256 manifest (if the provider allows)
are published.

13.2 Sealing. On receipt and before any featurisation: apply the content filter of 10.3 (a pickle stream
or a zip with a .pkl member; object .npy out of scope and counted), write the sorted SHA-256 manifest and
record its hash in the amendment log. Files whose SHA-256 is in the 1,008-file SafePickle download are
removed and counted. Files that share a structural group (section 2) with the 886 unique files are kept
but flagged; the PRIMARY analysis uses the non-overlapping ("novel") files, the secondary analysis all files.

13.3 Training. Every detector is trained once on all 886 unique corpus files (747 dev + 139 locked; the
locked set is already consumed by the final run of 2026-10-05), with the recipes and thresholds of the
final run: FUSE, FUSE-INV, FUSE-C, SP-RF, SP-CB, META (threshold 0.5), ML ensemble (inner-CV threshold)
and CNN (its v1 recipe). No tuning, no threshold change, no feature change after the manifest is sealed.

13.4 Scoring, once. The sealed set is scored in a single run; the code refuses a second run (once-only
marker and manifest check, as in 6 and F-96). The code is committed before the set is opened.

13.5 Metrics. Per detector: recall with a Wilson 95 % interval; if benign files are supplied, false-alarm
rate with a Wilson interval and F1 (secondary). Every row is also reported +FC (10.1, 10.4). META is
mandatory. Primary comparison: FUSE against SP-RF and SP-CB on the novel malicious files, exact McNemar,
Holm over the two. Wording rule for the paper: "FUSE detects more files of the unseen source" only if FUSE
wins after Holm (p < 0.05); otherwise the result is reported as comparable, with the recall intervals.
No non-inferiority test is run unless at least 200 novel malicious files remain (power_analysis.md).

13.6 Reporting. Whatever the outcome, the result is reported in the paper and in FAILURE_LOG if it is
unfavourable; the leave-one-source-out result of 12.2 stays as reported.

13.7 Source fixed (2026-10-07, before any file is downloaded). The external malicious source is
MalHug (Zhao et al., ASE 2024): the metadata table `malhug_result_info.csv` of github.com/security-pride/MalHug
and the repository archives of Zenodo record 13850049. For every row of type "model", the files named in
the `files` column (the part before ":") whose name ends in .pkl, .pickle, .pt, .pth, .bin, .th, .ckpt or
.data are extracted from that repository's archive (regular files only, never loaded) and labelled
malicious. No other file of an archive is used. ShadowPickle's test set (synthetic) is not part of this
evaluation.

13.8 Exclusions, applied before scoring and counted: content filter (10.3); duplicates; SHA-256 in the
1,008-file SafePickle download; SHA-256 in the PickleBall sealed half (`data/pickleball_sealed_shas.json`,
81 unique hashes of 88 members; the explore half's malicious files were already in the corpus); SHA-256 starting with the
hash prefix of an official torchvision checkpoint (section 15 list), since some MalHug repositories also
hold an unmodified official file. Rows whose archive is missing are counted.

13.9 Storage. The files stay on the Colab runtime's local disk (about 15 GB); only the seal JSON and the
results are written to Drive. Sealing and scoring happen in the same runtime, after the manifest hash is
recorded in this amendment log.

## 14. Additions of 2026-10-07 (reviewer-driven development analyses; BEFORE their results)

Written after an external review of the manuscript asked for a metadata-balanced evaluation and a
three-way output instead of fail-open. Neither result exists when this is written. Both analyses reuse
the saved out-of-fold predictions of the FUSE development run (`results/fuse/v2/fuse_cv_rep{0..4}.json`)
and `results/fuse/v2/file_meta.json`; nothing is retrained, and neither the locked set nor the PickleBall
sealed half is touched. Development files are those with a repetition-0 prediction (747). Code:
`metadata_tristate_eval.py`. Both are exploratory.

14.1 Metadata-hard subset. The shortcut stratum is every bare pickle of at most 4 KB
(`container == "pickle"` and `file_bytes <= 4096`). H is the set of development files outside it.
Primary: repetition-0 pooled out-of-fold F1, precision, recall and false alarms on H for FUSE, FUSE-INV,
FUSE-C, SP-RF, SP-CB, META, ML and CNN; paired stratified bootstrap of the F1 difference (section 4
method, 10,000 resamples) and exact McNemar for FUSE against SP-RF, SP-CB and META, Holm over the three
bootstrap p-values. Secondary: mean and SD of F1 on H over the five repetitions; recall and false alarms
per stratum of container (pickle / zip / other) by size band (<= 4 KB, 4 KB-1 MB, 1-16 MB, > 16 MB).
Wording rule: the paper says FUSE's margin "survives the metadata shortcut" only if FUSE beats META on H
after Holm (p < 0.05); otherwise the two are reported as comparable on H. The detectors were trained on
all strata, so H re-weights the evaluation and does not remove the shortcut from training; the paper
says so.

14.2 Three-way policy. Verdict = UNVERIFIED if `meta_baseline.cap_reason(meta)` is not None (byte_cap,
op_cap, malformed; section 10.1), else MALICIOUS if the detector's repetition-0 prediction is 1, else
SAFE. Reported on the development files: the number of benign and malicious files routed to UNVERIFIED,
by reason; for each detector, F1, recall and false alarms on the verified files only; and the policy view,
in which an UNVERIFIED malicious file counts as caught (sent to review) and an UNVERIFIED benign file
counts as review load, not as a false alarm. Review load = UNVERIFIED benign files / benign files.
The helper `tristate.py` implements the verdict function used here.

## 15. Additions of 2026-10-07 (official benign checkpoints; BEFORE any such file is downloaded)

Reason: on the locked test FUSE raised one false alarm among 64 benign files where SafePickle raised none,
and 64 files cannot bound a false-alarm rate tightly. Written before any official checkpoint was
downloaded or featurised. Code: `external_eval.py --official-benign`.

15.1 Source. The 166 weight files of the torchvision 0.26.0 model registry, all hosted on
download.pytorch.org/models. The list is `data/official_benign_torchvision.json` (sha256 62811c60...).
No Hugging Face file is used. Each file is downloaded in Colab, its SHA-256 checked against the hash
prefix in its file name where the name carries one (162 of 166; a mismatch excludes the file and is
counted), read statically (never unpickled or loaded), featurised and deleted. Files whose SHA-256 is in
the 1,008-file SafePickle download are removed and counted. The content filter of 10.3 applies.

15.2 Training. As in 13.3: every detector is trained once on all 886 unique corpus files with the
recipes and thresholds of the final run. Nothing is tuned on these files.

15.3 Metrics. Per detector: false alarms k/n with a Wilson 95 % interval, as built and +FC; under the
three-way policy of 14.2, the number of files returned UNVERIFIED (review load) and false alarms among
the verified files. Primary comparison: FUSE against SP-RF and SP-CB on these benign files, exact McNemar
on their false alarms, Holm over the two. Wording rule: the paper says FUSE "raises fewer false alarms
than SafePickle on official checkpoints" only if FUSE wins after Holm (p < 0.05), "more" only if it loses
after Holm, and otherwise reports them as comparable with the intervals. Every result is reported.

15.4 Once only. The set is scored in a single run; the code writes a once-only marker and refuses a
second run.

## 16. Additions of 2026-10-07 (read-cap experiment; BEFORE any result)

Reason: under the three-way verdict (14.2) 34 benign development files (6.9 %) go to review, 33 of them
because their raw pickle stream (17-59 MB) exceeds the 16 MiB read cap. Written before the experiment
was run or its code executed on the corpus. Code: `cap_eval.py`. Exploratory, development files only;
the locked set and the PickleBall sealed half are not scored.

16.1 Design. The same harness is run twice on the corpus files, re-featurised from the bytes: a control
with the frozen cap (16 MiB) and a treatment with 64 MiB. The cap is raised at run time
(picklescan_ml.features / semantic module constants); no frozen file is edited and nothing else changes
(MAX_OPS stays 10^6). Both runs use the original development files, groups and fold seed, so the folds
are those of the FUSE run (results/fuse/v2, repetition 0), and train FUSE, FUSE-INV, FUSE-C, SP-RF,
SP-CB, META, the ML ensemble and the CNN exactly as fuse_eval.dev_cv does.

16.2 Control check. The control must reproduce the saved repetition-0 predictions of FUSE, SP-RF, SP-CB
and META exactly (the CNN is not deterministic across runtimes and is excluded from the check). If it
does not, the experiment is reported as not interpretable and no treatment number is used.

16.3 Outcomes (treatment vs control, repetition 0). Primary: benign development files returned
UNVERIFIED (review load) and malicious files returned UNVERIFIED. Secondary: F1, false alarms and
misses per detector, as built and on verified files only; paired bootstrap of the F1 change per detector
(section 4 method); FUSE vs SP-RF and SP-CB non-inferiority at the 64 MiB cap; featurisation time per file
for the over-cap files. Wording rule: the paper may say a larger cap "removes most of the review load at
no loss in accuracy" only if the review load falls by at least half and no detector's F1 change has a
95 % interval below -0.01; otherwise it reports the numbers as measured.

## 17. Additions of 2026-10-10 (reviewer-driven; BEFORE any of these results and before any MalHug file is received)

Reason: the meta-review asks whether the canonical form adds detection value beyond metadata and the
SafePickle opcode histogram, and how the semantics-based detector behaves on an unseen source. Written
before `ablation_eval.py` was run on the corpus and before any MalHug file was fetched, sealed or scored.

17.1 Ablation design (exploratory, development files only). FUSE's five feature blocks are SafePickle
opcode frequency (SPF), semantic canonical frequency (SF), semantic stats (ST), the META vector (M) and
the v1 scalars (V1). Variants, all trained with the FUSE model (RF 500 + HistGB, threshold 0.5) on the
folds of the FUSE run (five repetitions, StratifiedGroupKFold seed = repetition, original groups):
FUSE (all), FUSE-noSPF, FUSE-noCANON (drops SF and ST), FUSE-noMETA, FUSE-noV1, CANON-only (SF + ST),
SPF-only, META-only. Features come from the frozen-cap (16 MiB) stage-1 cache of `cap_eval.py --cap-mib 16`.
The locked set and the PickleBall sealed half are not scored.

17.2 Control. The re-fitted FUSE must reproduce the saved FUSE predictions (results/fuse/v2) of every
repetition; otherwise the ablation is reported as not interpretable.

17.3 Outcomes. F1 per variant (repetition 0 and mean ± sd over five) on all development files and on
the metadata-hard subset H of 14.1; paired bootstrap (section 4 method) of FUSE minus each of the four
drop-one variants on repetition 0, Holm over the four, per set. Wording rule: the paper may say "the
canonical-form branch adds measurable accuracy" only if FUSE − FUSE-noCANON is positive with Holm
p < 0.05 on the development set or on H; otherwise it says "no measurable accuracy contribution of the
canonical-form branch on this corpus", and the canonical form is argued only through its invariance
properties (Theorems 1 and 2), not through accuracy.

17.4 Second external hypothesis (amends 13.5; confirmatory). Motivation, stated before any MalHug data:
in the exploratory leave-one-source-out test (12.2) FUSE-INV recalled 0.582 of the held-out
pickle-curated source against 0.467 for SP-RF at the same false-alarm rate. On the novel MalHug malicious
files, FUSE-INV is compared with SP-RF and SP-CB by exact McNemar, Holm over the two, at alpha 0.025
(a separate family from 13.5's FUSE family, whose alpha 0.05 is unchanged). Wording rule: "FUSE-INV
detects more files of the unseen source than SafePickle" only if both Holm-adjusted p < 0.025 with
FUSE-INV right more often; otherwise "comparable", with the recall intervals. Implemented in
`external_eval.summarise_malicious` (`mcnemar_fuseinv_novel_malicious`, `wording_fuseinv`).

## 18. Additions of 2026-10-10 (reviewer-driven reframing; BEFORE any of these results)

Reason: the detector ties SafePickle on clean-set F1 (the paper's own criticism of that metric). The
honest contribution is on the axes where the tie dissolves: worst-case robustness, false alarms at
realistic scale, and no fail-open. Sections 18.1-18.3 are written before `robustness_profile.py`,
`hybrid_eval.py` and the widened benign scale-up were run. The locked set and the PickleBall sealed
half are not re-scored by any of them.

18.1 Robustness profile (presentation of ALREADY-SAVED development results; no new scoring). The paper
reports a per-slice robustness table assembled from the saved repetition-0 out-of-fold predictions and
the saved protocol, container-stratified, inert-insertion and cap/fail-closed results (results/runall/v2
and results/fuse/v2), with `robustness_profile.py`. Slices: non-pickle ("other") containers; protocol
re-encoding (0-5) stability of the feature vector; inert-insertion worst-case evasion (attack study);
unverified / fail-open coverage (cap audit). Claim rule: the paper may say "FUSE (or FUSE-INV) is more
robust than SafePickle on <slice>" only where the saved numbers show SafePickle strictly worse on that
slice (e.g. F1 0.000 on non-pickle containers; a protocol-induced verdict flip; a malformed malicious
file passed as benign). It is reported slice by slice, never as a single aggregate robustness score,
and every input keeps its original exploratory/dev label.

18.2 Benign scale-up (amends section 15; confirmatory false-alarm estimate). The official-benign set is
widened from the 166 torchvision checkpoints to a hash-pinned catalogue of official checkpoints from
non-Hugging-Face hosts (torchvision, torchaudio, OpenMMLab, timm GitHub/fbaipublicfiles, Ultralytics,
Detectron2, OpenAI Whisper/CLIP). The catalogue (`data/official_benign_*.json`, each pinned by its own
SHA-256) is fixed before any file is downloaded. Each file is fetched over HTTPS from its official host,
its content hash is checked against the SHA prefix embedded in its name where one exists (a mismatch
drops the file and is logged, never scored), read statically (nothing is unpickled or loaded) and
discarded. Because free-Colab disk and bandwidth are finite, files are downloaded in ascending size
order under a fixed byte budget and the run is resumable; the paper reports the number actually scored
and the per-detector false-alarm rate with Wilson 95 % intervals, over whatever prefix of the catalogue
was scored. No success criterion is attached: the false-alarm rate is reported as measured. Scored once
(marker `EXTERNAL_OFFICIAL_DONE.json`); the catalogue and this protocol are frozen here.

18.3 Insertion-invariant hybrid FUSE-INV+ (exploratory, development files only). Motivation, fixed
before the result: pure FUSE-INV is insertion-invariant (Theorem 1) but gives up about 0.017 F1 against
SP-RF because it drops the raw opcode histogram and the metadata. FUSE-INV+ adds only features that are
still functions of the semantic canonical form, so insertion-invariance is preserved by construction:
canonical opcode UNIGRAM frequency (as FUSE-INV), canonical opcode BIGRAM frequency (normalised
histogram over the 68x68 canonical-opcode pairs of the canonical stream `sem_seq`), and the
canonical-graph stats INV_KEYS. Trained with the FUSE model (RF 500 + HistGB, threshold 0.5) on the
FUSE folds (five repetitions). Mandatory invariance self-test: the FUSE-INV+ feature vector must be
byte-identical for every file and every kept A1/A1b inert variant (the `fuse_eval` self-test extended to
the bigram block); if any variant differs the hybrid is reported as not invariant and no robustness
claim is made for it. Non-inferiority vs SP-RF and SP-CB (margin -0.02 F1, Holm) on the development set.
Wording rule: the paper may say "an insertion-invariant detector that matches SafePickle's development
accuracy" only if the invariance self-test passes on 100 % of variants AND FUSE-INV+ is non-inferior to
both SP-RF and SP-CB; otherwise it reports the numbers as measured and makes no matching claim.
FUSE-INV+ is exploratory and is NOT added to the locked-test final run (section 6), whose detector set
stays frozen.

## Amendment log

| Date | Change | Reason |
|---|---|---|
| 2026-10-02 | Plan fixed | - |
| 2026-10-02 | Section 2.1 names `COLAB_CELL.py` as the v1 selection procedure instead of `safepickle_colab.download_dataset` | Reading the repo showed the 1008-file run came from `COLAB_CELL.py`. Corrected before any v2 result existed. |
| 2026-10-02 | Added the v2 detector `CNNv2` (semantic-canonical-stream CNN + monotone evidence head + opcode-frequency branch, trained on the hardened synthetic set) and a third primary comparison P3 (CNNv2 vs SP-RF) under the same Holm family. | v2 design frozen after the step-3 error analysis, added before its dedicated Colab run. v2 is developed on the dev folds only; P3 and every CNNv2 number stay labelled exploratory until the section 6 locked-test final run. Local synthetic + attack results: clean F1 1.00 (5 seeds), nullifAI 16/16, provable padding monotonicity (score never drops), benign FP 0, and it beats a faithful SafePickle-frequency RF on nullifAI (16 vs 11) and under padding (1.00 vs 0.00). |
| 2026-10-03 | Section 9 added: non-inferiority margin (F1 -0.02, specificity -0.005), certified detection rate, CNNv2 locked-test contamination and its consequences, G1 outcome, in-the-wild scan protocol. | Added after the development results and before the locked test or any external set was opened. Corrects the previous row: CNNv2 was in fact tuned on all 888 files. |
| 2026-10-03 | Head-to-head of the token-fixed CNNv2 on all 888 files received (CNNv2@0.5 F1 0.9454, FP 10; SP-CB@0.5 F1 0.9465, FP 7). Recorded as exploratory under 9.3. Its ModelScan row (TP 0, FP 0) is a tool failure, not a result, and is not reported. CNNv2 is frozen at this version for the dev-fold and external runs. | Logged on receipt so later CNNv2 changes cannot be tuned against it silently. |
| 2026-10-04 | Received an external audit (`artifacts.zip/reports`, produced outside this repo). (a) A metadata-only baseline (file size, container, protocol) reaches dev F1 0.939-0.946, level with every learned detector, and 236 of 329 malicious files are bare pickles of at most 4 KB against 1 benign. (b) That audit fitted the metadata baseline on dev and scored it on the locked test (F1 0.973). Our detectors were not run on the locked test. (c) Replication run `v2_results (4)` (torch 2.11): ML 0.9405, CNN 0.9298, SP-RF 0.9467, P1/P2 again not significant. Consequences: the metadata baseline becomes a mandatory baseline in every table; a shape-matched benign set (same container/protocol/size cell as each malicious file, de-duplicated against the corpus) becomes a primary evaluation set before the final run; the first run (`v2_results (2)`) stays the confirmatory dev result, run 4 is reported as a replication. | Logged on receipt. The locked test's labels have now been looked at for one non-pre-registered baseline; this is disclosed in the paper. |
| 2026-10-04 | Received replication run `v2_results (3)` (torch 2.11 GPU, same split hash): ML 0.9405, CNN 0.9342, SP-RF 0.9489, SP-CB 0.9467; P1 p 0.338, P2 p 0.236 (Holm), not significant. Reported as a replication next to run 4; run 2 stays confirmatory. | Same conclusion in all three runs: faithful SafePickle numerically ahead, no significant difference. |
| 2026-10-04 | `colab_v2_eval.py` gains the metadata baseline `META` (logistic regression on container, protocol, sizes, member/stream counts, bytes after STOP; threshold 0.5; same folds, back-filled into existing checkpoints) and the section 9.1 non-inferiority test (`boot_noninferiority`, Holm over SP-RF/SP-CB per candidate). Applied offline to run 2's saved predictions: META dev F1 0.952 (mean fold 0.950), above every detector, none significantly different from it; CNN vs SP-RF/SP-CB lower bounds -0.0217/-0.0202 (margin -0.02, not non-inferior), ML -0.028/-0.027. | Exploratory on the dev set (the margin was fixed after seeing dev results). The confirmatory non-inferiority test is the final run on the locked test and the external sets. |
| 2026-10-04 | Section 10 added: fail-closed policy and `+FC` rows; guarantees scoped to the caps and the certified rate redefined; CNNv2 certificate withdrawn (token-gate counterexample); PickleBall explore/sealed split (salt `NED-pickleball-split-v1`); META/`+FC` mandatory everywhere; G-C reclassified; head-to-head universe disclosed; out-of-fold attack study. | Written after the code/results audit and BEFORE the first PickleBall explore run, real-file attack study, cap re-scan or final run. |
| 2026-10-04 | Protocol deviation disclosed: before section 10.3's split was used, the pre-amendment `pickleball_eval.py` (no split, extension-based member filter) was run once in Colab (53.7 min): 66 accepted members, 57 dropped as SHA/structural overlap with our corpus, 9 scored (2 malicious, 7 benign). Only aggregate counts exist (`results/pickleball_presplit_smoke_old_script.json`); no per-file result was produced or seen. It is a smoke test and is never reported as an estimate. | Logged on receipt, before any explore-half run. The 86 % overlap is itself reported: PickleBall is not independent of the SafePickle corpus. |
| 2026-10-04 | Before any COLAB_RUN_NEXT result: (a) synthetic experiments are re-run on `synth_v3.py` (seeds honoured; train/test disjoint by SHA-256 and structural group; modes random and family_out, 5 seeds); every earlier synthetic held-out number is withdrawn (FAILURE_LOG F-14, F-24) and synthetic results stay out of the abstract; (b) the head-to-head is re-run with the fixed `colab_headtohead.py` (886 files, conflicting-label hashes dropped, each fold's own threshold); the fixed-0.5 CNNv2+SP-CB ensemble is the only head-to-head comparison reported as a candidate result, with a paired bootstrap CI, exploratory (CNNv2 contamination, 9.3); (c) Step 6 timing uses `timing_real.py` on development files only (40 per size band, seed 0, 60 s limit per call). Already received before this entry and reported as exploratory: the out-of-fold real-file attack study (section 10.7) and the clean synth_v3 held-out accuracy. | Logged before COLAB_RUN_NEXT is run. |
| 2026-10-04 | Correction to 10.1: "no detector evaluated so far is fail-closed" is too broad; CNN, ML, SP-RF and SP-CB are not, but the weak SP-style copy flags all 35 over-cap dev files (with 41 false alarms overall). The rule-scanner false-alarm figures are suspended until `scanner_fp_diagnosis.py` has run (FAILURE_LOG F-86); logged before that result. | Found by the number-consistency audit. |
| 2026-10-04 | COLAB_RUN_NEXT results received (`results/runnext/`, bundle `3ed42b73`): (a) synth_v3 random/family_out, all exploratory and out of the abstract; (b) fixed head-to-head on 886 files: ensemble 0.9581 vs SP-CB 0.9495, ΔF1 +0.0086 [−0.0024, +0.0201], McNemar p 0.27, not significant; colab_headtohead.py did not compute the pre-registered CI, so it was computed afterwards from the saved per-file OOF probabilities with the pre-registered method (`headtohead_ci.json`; the universe is all 886 files as pre-registered and is never sliced by the locked manifest); (c) timing_real on dev files. Step 5b (`scanner_fp`) did not run because the session used the pre-`32b820e` notebook (FAILURE_LOG F-87); the F-86 suspension stands until it runs. | Logged on receipt, before the scanner diagnosis result. |
| 2026-10-04 | COLAB_RUN_ALL results received (`results/runall/`, bundle `43e2e66c` = committed harness at `f59bd5e`). The main CV was restored from Drive checkpoints (`cv_rep0..4`, the same computation already reported as run 4 / the 886 head-to-head — **not a new independent run**); RUN_ALL added the derived-stat suite and the new experiments. Locked manifest `1aaa27a4` reproduced; locked 139 held out and never scored. **(a)** META + non-inferiority back-filled on the restored folds: P1 ML vs SP-RF p 0.475, P2 CNN vs SP-RF p 0.082 (Holm 0.164), neither rejected; NI (margin −0.02 F1, Holm): ML non-inferior raw to SP-RF/SP-CB but fails after Holm (adj 0.0784), CNN **not** non-inferior (lower bound −0.0325); specificity NI fails for both. **(b)** Stratified reanalysis: SP-RF significantly leads the learned detectors on bare pickles (CNN p 0.0034, ML p 0.0156) but scores F1 0 on non-pickle containers, where META/ML/CNN recover (META Δ+0.875, p 0.0156). **(c)** Protocol test: semantic canonical stream identical across protocols 0–5 in 5/5 behaviours (Theorem 2); the SafePickle frequency vector is not (0/5; one SafePickle-CB verdict flip). **(d)** Cap audit + `cap_rescan.json`: 34 benign dev files are over-cap; fail-closed on all unverified costs 0.033–0.054 F1; the 16 MiB prefix front end verifies 0 of the 34 (R4). **(e)** Out-of-fold attack study reconfirmed (SP 0 / CNN@0.5 0 / ML 1 / CNN 1 / META 2 of 38). **(f)** PickleBall: the **explore** half only was scored; the **sealed** half was hashed (`990c452f`) and **never featurised** (0 members). After de-duplication against our corpus and the content/≤80 MB filter the explore half is degenerate — 1 benign unit, 0 malicious units — so **no external recall or FPR is reported** on it (FAILURE_LOG F-90); SafePickle's 0.8122 stays context only; the sealed half remains the single confirmatory external set for the final run. | Logged on receipt. No new analysis plan was introduced; the statistics are those pre-registered in sections 9–10. |
| 2026-10-05 | COLAB_RUN_ALL re-run received (`results/runall_1/`, bundle `17e1834d`). Its main step restored the **run-3** CV checkpoints (rep 0 CNN 0.9342, SP-RF 0.9489), so it is the derived-stat suite and the new experiments on the run-3 folds, not a new CV run. Unchanged: P1/P2 not rejected (P1 p 0.338, P2 Holm 0.236); CNN not non-inferior; front end verifies 0/34 benign over-cap files; semantic stream protocol-invariant 5/5; PickleBall explore 1 benign / 0 malicious unit (sealed half not featurised). Changed: ensemble NI vs SP-RF fails even before Holm (lower bound -0.0225, p 0.082), vs SP-CB passes only before Holm (p 0.047); attack study on run-3 folds: 35 files, SP-RF/SP-CB/ensemble/META 0 evaded, CNN 2, CNN@0.5 1 (A1b). | Logged on receipt. No analysis change. |
| 2026-10-05 | Section 11 added: fused detectors FUSE, FUSE-INV (primary) and FUSE-C (secondary), adoption rule and the meaning of "robust". FAILURE_LOG F-91 (A1b builtin-call block argument order) fixed before any FUSE attack run. | Written before any FUSE result. The final run stays single and is not run until the 11.4 decision is logged. |
| 2026-10-05 | Scope decision, no new analysis: R7 (CNNv2 rename re-measure), R9 (synthetic cap-crossing probe) and R12 (scoring of the family-held-out nullifAI set) are **not run**. The paper reports them as unmeasured and narrows the matching claims: CNNv2 is left out of the rename table, the cap blind spot rests on inspection plus the 35 real over-cap files, and Table V stays in-sample. R10 (shape-matched benign set) is **dropped**: it would need harvesting hub files, which section 10 and the ethics protocol rule out; the container- and size-stratified analysis stands in its place. Only R11 (the single final run) remains open. | Recorded before any of these results exists, so no result can have influenced it. |
| 2026-10-05 | COLAB_FUSE results received (`results/fuse/`, zip `ea0e8125`, bundle `7f8c2478`; locked set not scored). **Section 11.4 decision, logged before the final run:** FUSE **adopted** (non-inferior to SP-RF and SP-CB after Holm, lower bounds −0.0108/−0.0085; specificity 0.9959 vs SP-RF 0.9939; 0 evaded files in seeds 0 and 1). FUSE-INV **not adopted** (lower bound −0.0206 vs SP-RF, p 0.0528; 1 evaded file in seed 1, an A3 live insertion outside Theorem 1). FUSE-C fails and is significantly worse than SP-RF. FUSE is not superior to SP-RF, SP-CB or META. The final run (section 6) therefore scores every frozen detector, META and FUSE* once; FUSE is reported as the adopted detector, with no proof-based robustness claim (11.5). | Logged on receipt; the decision applies the 11.4 rule mechanically. |
| 2026-10-05 | Section 12 added: architecture comparison (CNN / BiLSTM / Transformer in one harness) and leave-one-source-out shift test, both exploratory on dev; FUSE added to the PickleBall sealed-half final run. | Reviewer requests; written before any of these results exists. |
| 2026-10-05 | **Final run, part 1 (locked test) executed once** by the author from `COLAB_FUSE.ipynb` cell 6 at 09:47 UTC (bundle `7f8c2478`), after the 11.4 decision was committed (01:54 UTC). Manifest `1aaa27a4…` as pre-registered; results in `results/final/`. F1 on the 139 locked files: FUSE 0.973, FUSE-INV / FUSE-C / SP-RF / SP-CB / SP-AE / META 0.9726, ML and CNN 0.9589. FUSE non-inferior to SP-RF and SP-CB in F1 (lower bound −0.0132, Holm p 0.016), specificity non-inferiority not shown (1 false alarm vs 0); not superior to anything. ML and CNN not non-inferior (−0.036). The same session re-ran the FUSE dev CV and attack study on a different stage-1 cache (run-4 row order, so run-4 folds): FUSE again passes 11.4 (lower bound +0.0161; 0 evaded files in both seeds) and FUSE-INV would also pass there (−0.0172; 0 evaded). The 11.4 decision stands as logged (made on the first received run), and both fold sets are reported (FAILURE_LOG F-94). | Logged on receipt. Part 2 (PickleBall sealed half) is still to run. |
| 2026-10-05 | **Deviation:** the locked test was scored a second time at 12:18 UTC from a session whose Drive held no once-only marker (FAILURE_LOG F-96). The first run (09:47) remains the confirmatory result; the repeat is reported as such. The code now refuses any further locked-test run. | Logged on receipt. |
| 2026-10-05 | COLAB_FINAL received (`results/final_colab/`, bundle `1d0b8525`). 12.1: CNN ≈ BiLSTM (ΔF1 −0.002, p 0.73), CNN > Transformer (−0.019, Holm 0.012). 12.2: leave-one-source-out recall on held-out curated malicious files 0.47–0.58 for every detector (in-distribution 0.80–0.89); PickleCloak held out 0.86–1.00. **Final run, part 2:** PickleBall sealed half scored once (manifest `990c452f` matches): 2 malicious / 4 benign files after de-duplication; FUSE, FUSE-C, SP-RF 2/2 and 0/4; descriptive only. The second locked-test run's JSON (F-96) is archived as `results/final/final_locked_results_second_run_1218.json`. | Logged on receipt. No analysis change. Every pre-registered run is now complete. |
| 2026-10-06 | Section 13 added: protocol for an external malicious source (sealing, training on all 886 unique files, single scoring run, McNemar FUSE vs SP-RF/SP-CB with Holm, wording rule). | Leave-one-source-out recall about 0.5 (12.2); written before any external file was requested or received. |
| 2026-10-07 | Section 14 added: metadata-hard subset (bare pickles <= 4 KB removed) with FUSE vs SP-RF/SP-CB/META tests and a wording rule; three-way SAFE/MALICIOUS/UNVERIFIED policy on dev. | External review (metadata shortcut, fail-open caps); written before either result, from saved dev predictions only. |
| 2026-10-07 | Section 14 results (`results/meta_tristate/`, from saved dev predictions). 14.1: on H (563 files, 71 malicious) F1 FUSE 0.857, META 0.827, SP-RF 0.813, SP-CB 0.803; FUSE vs SP-RF/SP-CB/META not significant (Holm 0.59-0.61), wording "comparable". 14.2: UNVERIFIED 34 benign (6.9 %) + 18 malicious; on verified files SP-RF F1 0.976 vs FUSE 0.956, policy recall 0.969 vs 0.929 (FAILURE_LOG F-97). | Reported as pre-registered, whatever the outcome. |
| 2026-10-07 | Section 15 added: false-alarm check on the 166 official torchvision checkpoints (list hash 62811c60...), trained on all 886 unique files, McNemar FUSE vs SP-RF/SP-CB with Holm, wording rule, once-only run. | One false alarm vs none on 64 locked benign files; written before any official file was downloaded. |
| 2026-10-07 | Sections 13.7-13.9 added: external source fixed as MalHug (Zenodo 13850049, CSV-named pickle-family files), exclusions (SafePickle download, PickleBall sealed half, official torchvision checkpoints), local storage. | Dataset search of 2026-10-07 (no released independent in-the-wild set without overlap risk); written before any MalHug file was downloaded. |
| 2026-10-07 | Section 16 added: 16 MiB vs 64 MiB read-cap experiment on dev (control must reproduce saved repetition-0 predictions; primary outcome review load; wording rule). | Review load 6.9 % under the three-way verdict; written before the experiment ran. |
| 2026-10-07 | Section 16 implementation note (before any result): each file keeps its original group (`data/dev_reference.json`), so folds are identical in both runs even if a larger cap changes a structural hash; ML and CNN are trained per fold with `colab_v2_eval.run_fold`, as in the main v1 run (`fuse_eval.dev_cv` attaches them from saved files instead). | Clarifies 16.1 wording; no result exists. |
| 2026-10-10 | Section 17 added: per-signal ablation of FUSE (dev only) and a second, separately alpha-controlled external hypothesis, FUSE-INV vs SafePickle on novel MalHug files (amends 13.5). | Meta-review requests; written before the ablation was run and before any MalHug file was fetched. |
| 2026-10-10 | 16.2 amended and `cap_eval.align` made drift-tolerant. Control check: the deterministic detectors (SP-RF, SP-CB, META) must still reproduce the saved rep-0 predictions EXACTLY; FUSE and FUSE-C, which include a HistGradientBoosting component that is not bit-identical across platforms, must agree to within 2 % of files (CONTROL_TOL). `align` now matches the 747 reference development files by sha256 (reference order, groups restored), tolerating upstream corpus drift (extra or duplicate files) but erroring if any reference development file is absent. | The frozen-cap control run reproduced SP-RF/SP-CB/META exactly (0/747 differ) but FUSE differed on 9/747 files (1.2 %) and FUSE-C on 10/747, purely from HistGradientBoosting non-determinism; the old exact-match rule mislabelled an otherwise-reproducing run "not interpretable" (FAILURE_LOG F-98). Amended before using the treatment FUSE numbers; the non-inferiority anchors SP-RF/SP-CB reproduce exactly, so no conclusion rests on the tolerated drift. |
| 2026-10-10 | Section 18 added: robustness profile from saved dev results (18.1), benign scale-up to a hash-pinned multi-source official catalogue amending section 15 (18.2), and an exploratory insertion-invariant hybrid FUSE-INV+ on dev only (18.3). | Reviewer reframing onto robustness / false-alarm / no-fail-open axes; written before robustness_profile.py, hybrid_eval.py and the widened benign run were executed. |
| 2026-10-11 | 16.2/17.2 amended (upstream-drift intersection). When one or more of the 747 reference development files is no longer obtainable from the upstream public datasets, `cap_eval.align` no longer errors by default: it runs the ablation (17) and the insertion-invariant hybrid (18.3) on the available intersection, records the absent SHA-256s in a `drift` block in each result, and re-fits FUSE on those same files as the internal reference so that every FUSE-vs-variant comparison uses identical folds. The saved-prediction control (16.2) is not expected to pass under drift (the folds differ from the 747-file primary run) and the result is still interpretable because the ablation's claims are paired comparisons on one fixed file set; the summary wording then carries the explicit caveat "computed on the N-file intersection after upstream corpus drift". The strict hard-error behaviour is preserved and is required for the locked final run via `V2_STRICT_ALIGN=1`. | Eight of the 747 development files had been removed from the upstream Hugging Face datasets by the time the ablation/hybrid were re-run, so a full re-download could never reproduce the exact 747-file set; erroring left the two reviewer-requested analyses unrunnable. The amendment is written before those numbers are used; the primary 747-file development and locked-test results are unchanged, and no headline claim rests on the intersection run. |
