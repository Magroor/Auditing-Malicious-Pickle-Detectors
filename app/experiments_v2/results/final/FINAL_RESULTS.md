# Final run: locked test (scored once, 2026-10-05 09:47 UTC)

Run from `COLAB_FUSE.ipynb` cell 6 (bundle `7f8c2478`, the code before the F-93 manifest check; the manifest recorded is the pre-registered `1aaa27a4…`). Training: all 747 dev files; scoring: the 139 locked files (64 benign / 75 malicious), once. The 11.4 decision (FUSE adopted, FUSE-INV not) was committed at 01:54 UTC, before this run. Wilson intervals added offline from the confusion counts.

| Detector | F1 | Precision | Recall [Wilson 95%] | False alarms [Wilson 95%] | AUC | F1 +FC |
|---|---|---|---|---|---|---|
| ML | 0.9589 | 0.9859 | 0.9333 [0.8532, 0.9712] | 1/64 [0.0028, 0.0833] | 0.9792 | 0.9333 |
| CNN | 0.9589 | 0.9859 | 0.9333 [0.8532, 0.9712] | 1/64 [0.0028, 0.0833] | 0.9629 | 0.9272 |
| CNN@0.5 | 0.9524 | 0.9722 | 0.9333 [0.8532, 0.9712] | 2/64 [0.0086, 0.107] | 0.9629 | 0.9272 |
| SP-style | 0.9333 | 0.9333 | 0.9333 [0.8532, 0.9712] | 5/64 [0.0338, 0.1702] | 0.9804 | 0.9333 |
| SP-RF | 0.9726 | 1.0 | 0.9467 [0.8707, 0.9791] | 0/64 [0, 0.0566] | 0.9805 | 0.9474 |
| SP-CB | 0.9726 | 1.0 | 0.9467 [0.8707, 0.9791] | 0/64 [0, 0.0566] | 0.9889 | 0.9474 |
| SP-AE | 0.9726 | 1.0 | 0.9467 [0.8707, 0.9791] | 0/64 [0, 0.0566] | 0.967 | 0.9474 |
| SP-RF-tuned | 0.9726 | 1.0 | 0.9467 [0.8707, 0.9791] | 0/64 [0, 0.0566] | 0.9805 | 0.9474 |
| SP-RF+synth | 0.951 | 1.0 | 0.9067 [0.8197, 0.9541] | 0/64 [0, 0.0566] | 0.9801 | 0.9262 |
| META | 0.9726 | 1.0 | 0.9467 [0.8707, 0.9791] | 0/64 [0, 0.0566] | 0.9865 | 0.9404 |
| FUSE | 0.973 | 0.9863 | 0.96 [0.8889, 0.9863] | 1/64 [0.0028, 0.0833] | 0.979 | 0.9474 |
| FUSE-C | 0.9726 | 1.0 | 0.9467 [0.8707, 0.9791] | 0/64 [0, 0.0566] | 0.9791 | 0.9474 |
| FUSE-INV | 0.9726 | 1.0 | 0.9467 [0.8707, 0.9791] | 0/64 [0, 0.0566] | 0.9789 | 0.9474 |

Non-inferiority (margin −0.02 F1; Holm over SP-RF/SP-CB; adjusted p shown monotone, F-92):
- FUSE: vs SP-RF lower bound -0.0132, Holm p 0.016, non-inferior; specificity lower bound -0.0469 (not NI); vs SP-CB lower bound -0.0132, Holm p 0.016, non-inferior; specificity lower bound -0.0469 (not NI)
- FUSE-INV: vs SP-RF lower bound 0.0, Holm p 0, non-inferior; specificity lower bound 0.0 (NI); vs SP-CB lower bound 0.0, Holm p 0, non-inferior; specificity lower bound 0.0 (NI)
- FUSE-C: vs SP-RF lower bound 0.0, Holm p 0, non-inferior; specificity lower bound 0.0 (NI); vs SP-CB lower bound 0.0, Holm p 0, non-inferior; specificity lower bound 0.0 (NI)
- ML: vs SP-RF lower bound -0.036, Holm p 0.7494, not shown; specificity lower bound -0.0469 (not NI); vs SP-CB lower bound -0.036, Holm p 0.7494, not shown; specificity lower bound -0.0469 (not NI)
- CNN: vs SP-RF lower bound -0.0364, Holm p 0.7402, not shown; specificity lower bound -0.0469 (not NI); vs SP-CB lower bound -0.0364, Holm p 0.7402, not shown; specificity lower bound -0.0469 (not NI)

Superiority (paired bootstrap ΔF1):
- FUSE: vs SP-RF 0.0004 [-0.0196, 0.0211], p 0.9618; vs SP-CB 0.0004 [-0.0196, 0.0211], p 0.9618; vs META 0.0004 [-0.0196, 0.0213], p 0.9386
- FUSE-INV: vs SP-RF 0.0 [0.0, 0.0], p 1.0; vs SP-CB 0.0 [0.0, 0.0], p 1.0; vs META 0.0 [-0.021, 0.0213], p 1.0
- FUSE-C: vs SP-RF 0.0 [0.0, 0.0], p 1.0; vs SP-CB 0.0 [0.0, 0.0], p 1.0; vs META 0.0 [-0.021, 0.0213], p 1.0
- ML: vs SP-RF -0.0137 [-0.042, 0.0139], p 0.436; vs SP-CB -0.0137 [-0.042, 0.0139], p 0.436; vs META -0.0137 [-0.035, 0.0], p 0.255
- CNN: vs SP-RF -0.0137 [-0.0424, 0.0139], p 0.4326; vs SP-CB -0.0137 [-0.0424, 0.0139], p 0.4326; vs META -0.0137 [-0.0351, 0.0], p 0.2604

Reading: FUSE is confirmed non-inferior in F1 to both SafePickle versions on the locked test (lower bound −0.0132), with 1 false alarm against 0 for SafePickle, so specificity non-inferiority (margin −0.005) is not shown. FUSE, FUSE-INV, FUSE-C, SP-RF, SP-CB and META all score F1 0.97; nothing is superior. The v1 ML ensemble and CNN are not non-inferior here (lower bound −0.036).
