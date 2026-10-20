"""Validate our detector on the PUBLIC SafePickle corpus — runs on Colab only.

This script is meant to run inside the isolated Google Colab VM (via the
colab_bridge), because the SafePickle malicious files are REAL payloads
(reverse shells, credential stealers). It is safe by construction: every file
is read as raw bytes and analysed STATICALLY. It never calls pickle.load,
pickle.loads or torch.load on any sample, so no payload is ever executed.

Pipeline:
  1. Train our detector (Random Forest + XGBoost ensemble, plus the 1D CNN) on
     the synthetic generator. No real file is used for training.
  2. Download the public SafePickle dataset from Hugging Face (HFscanner1231).
     The paper headline is 648 benign / 79 malicious, but the released malware
     datasets hold many more, so the actual pull is 648 benign / 428 malicious
     for the zero-shot scan and 864 files (450 benign / 414 malicious) for the
     leakage-free cross-validation.
  3. Scan every real file with our detector and with picklescan, ModelScan and
     fickling, all statically.
  4. Report precision, recall, F1 and specificity per detector.

Expected honest outcome: our numbers on this REAL data will be lower than the
0.99/1.00 measured on cleanly separable synthetic data, while the denylist
tools fall further (SafePickle reports picklescan 0.19, ModelScan 0.19,
fickling 0.63 on this set). This is the external-validity result.
"""
from __future__ import annotations

import glob
import json
import logging
import os
import subprocess
import sys
import time

# The static scanners emit a log line per dangerous import found, which floods
# the output and slows the run to a crawl on a malware corpus. Silence it. This
# only affects logging, not the scan verdicts.
logging.disable(logging.CRITICAL)

RESULTS = "/content/results/safepickle_results.json"


def _ensure_deps():
    """Install the static scanners and helpers in the Colab VM if missing."""
    pkgs = ["picklescan", "modelscan", "fickling", "xgboost", "huggingface_hub"]
    for p in pkgs:
        mod = {"huggingface_hub": "huggingface_hub"}.get(p, p)
        try:
            __import__(mod)
        except Exception:
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", p], check=False)


def download_dataset(dest="/content/safepickle"):
    from huggingface_hub import snapshot_download
    repos = ["pickle-curated", "pickle-malwares", "pickle-picklecloak"]
    for r in repos:
        try:
            snapshot_download(repo_id=f"HFscanner1231/{r}", repo_type="dataset",
                              local_dir=os.path.join(dest, r))
        except Exception as e:
            print(f"  warning: could not fetch {r}: {e}")
    return dest


def collect_files(dest="/content/safepickle"):
    """Label by directory: files/benign/* -> 0, files/malicious/* -> 1. Bytes only."""
    items = []
    for f in glob.glob(os.path.join(dest, "**", "benign", "*"), recursive=True):
        if os.path.isfile(f):
            items.append((f, 0))
    for f in glob.glob(os.path.join(dest, "**", "malicious", "*"), recursive=True):
        if os.path.isfile(f):
            items.append((f, 1))
    return items


def main():
    import numpy as np
    from sklearn.metrics import f1_score, precision_score, recall_score

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    _ensure_deps()

    from picklescan_ml.deep import train_cnn
    from picklescan_ml.rules import real_fickling, real_modelscan, real_picklescan
    from picklescan_ml.scan import Scanner
    from train_deep import augmented_training

    print("[1/4] Training our detector on synthetic data (no real file used) ...")
    scanner = Scanner.load_or_train()
    blobs, labels = augmented_training()
    cnn = train_cnn(blobs, labels, epochs=40, seed=0)

    print("[2/4] Downloading the public SafePickle corpus ...")
    download_dataset()
    items = collect_files()
    nb = sum(1 for _p, l in items if l == 0)
    nm = sum(1 for _p, l in items if l == 1)
    print(f"      files: {len(items)}  (benign {nb}, malicious {nm})")
    if not items:
        print("      no files found — check the dataset layout.")
        return

    print("[3/4] Static scan with every detector (never executes a sample) ...")
    detectors = {
        "ML (ours)": lambda b: scanner.scan_bytes(b).final_verdict == "malicious",
        "CNN (ours)": lambda b: bool(cnn.predict(b)),
        "picklescan": real_picklescan,
        "ModelScan": real_modelscan,
        "fickling": real_fickling,
    }
    y = np.array([l for _p, l in items])
    preds = {d: [] for d in detectors}
    t0 = time.time()
    for i, (path, _lab) in enumerate(items):
        try:
            with open(path, "rb") as fh:
                data = fh.read()          # raw bytes only — never deserialised
        except Exception:
            data = b""
        for d, fn in detectors.items():
            try:
                preds[d].append(int(bool(fn(data))))
            except Exception:
                preds[d].append(0)
        if i % 100 == 0:
            print(f"      {i}/{len(items)}")
    print(f"      scanned in {time.time() - t0:.0f}s")

    print("[4/4] Metrics on the real corpus:")
    out = {"n": len(items), "n_benign": int(nb), "n_malicious": int(nm), "detectors": {}}
    for d in detectors:
        p = np.array(preds[d])
        spec = float(((p == 0) & (y == 0)).sum() / max((y == 0).sum(), 1))
        out["detectors"][d] = {
            "precision": round(float(precision_score(y, p, zero_division=0)), 3),
            "recall": round(float(recall_score(y, p, zero_division=0)), 3),
            "f1": round(float(f1_score(y, p, zero_division=0)), 3),
            "specificity": round(spec, 3),
        }
    print(json.dumps(out, indent=2))
    os.makedirs(os.path.dirname(RESULTS), exist_ok=True)
    with open(RESULTS, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nSaved results to {RESULTS}")
    # If Drive is mounted, also persist there so it survives a runtime recycle.
    drive = "/content/drive/MyDrive/colab_ckpts"
    if os.path.isdir("/content/drive/MyDrive"):
        os.makedirs(drive, exist_ok=True)
        with open(os.path.join(drive, "safepickle_results.json"), "w") as fh:
            json.dump(out, fh, indent=2)
        print(f"Also saved to {drive}/safepickle_results.json")


if __name__ == "__main__":
    main()
