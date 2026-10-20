"""High level scanner used by the user interface and the tests."""

from __future__ import annotations

import io
import os
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np

from .features import FEATURE_NAMES, MAX_STREAM_BYTES, featurize
from .rules import rule_scan

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MODEL = os.path.join(os.path.dirname(HERE), "models", "detector.joblib")

# A container can hold more than one pickle. features.unwrap deliberately returns a
# single stream, because every experiment in the thesis scores one stream per file,
# so the scanner walks the remaining members here instead. Without this a benign
# data.pkl sitting beside a malicious second pickle reads as clean, since the second
# member is never parsed at all. The two ceilings below bound the walk, so a hostile
# archive with a huge member list cannot turn one upload into a long scan.
MAX_ARCHIVE_MEMBERS = 32
_PICKLE_SUFFIXES = (".pkl", ".pickle", ".pck", ".pkt", ".bin", ".pt", ".pth", ".dat")


def archive_members(data: bytes) -> List[Tuple[str, bytes]]:
    """Return every extra member of a ZIP container that could hold a pickle.

    The first member that features.unwrap already returns is left out, because the
    caller has scanned it as the main stream. Members are read with the same size
    ceiling as the main stream, therefore a zip bomb cannot expand here either.
    """
    if data[:2] != b"PK":
        return []
    try:
        import zipfile
        z = zipfile.ZipFile(io.BytesIO(data))
        names = z.namelist()
    except Exception:
        return []
    primary = [n for n in names if n.endswith("data.pkl")] or [n for n in names if n.endswith(".pkl")]
    skip = primary[0] if primary else None
    out: List[Tuple[str, bytes]] = []
    for name in names:
        if name == skip or name.endswith("/"):
            continue
        if not name.lower().endswith(_PICKLE_SUFFIXES):
            continue
        try:
            with z.open(name) as fh:
                blob = fh.read(MAX_STREAM_BYTES + 1)
        except Exception:
            continue
        if blob:
            out.append((name, blob))
        if len(out) >= MAX_ARCHIVE_MEMBERS:
            break
    return out


@dataclass
class ScanResult:
    filename: str
    size: int
    ml_verdict: str
    ml_confidence: float
    rule_verdict: str
    rule_reasons: List[str]
    imports: List[Tuple[str, str]]
    suspicious_imports: List[Tuple[str, str]]
    opcodes: List[Tuple[str, object, int]]
    parse_error: bool
    proto_version: int
    n_ops: int
    byte_tokens: List[str] = field(default_factory=list)
    nonallowlisted_globals: List[Tuple[str, str]] = field(default_factory=list)
    picklescan_dangerous: int = 0
    top_features: List[Tuple[str, float, float]] = field(default_factory=list)
    scanned_members: List[str] = field(default_factory=list)
    flagged_member: str = ""

    @property
    def agree(self) -> bool:
        return (self.ml_verdict == "malicious") == (self.rule_verdict == "malicious")

    @property
    def final_verdict(self) -> str:
        """Combine both detectors. If either is confident of malice, warn."""
        if self.ml_verdict == "malicious" or self.rule_verdict == "malicious":
            return "malicious"
        if self.rule_verdict == "suspicious":
            return "suspicious"
        return "benign"


class Scanner:
    """Loads the trained model once and scans pickle byte strings."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or DEFAULT_MODEL
        self._bundle = None

    @property
    def bundle(self):
        if self._bundle is None:
            import joblib
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(
                    f"No trained model at {self.model_path}. "
                    "Run python -m picklescan_ml.train first.")
            self._bundle = joblib.load(self.model_path)
        return self._bundle

    @classmethod
    def load_or_train(cls, model_path: Optional[str] = None) -> "Scanner":
        sc = cls(model_path)
        if not os.path.exists(sc.model_path):
            from .train import train
            train()
        return sc

    def _top_features(self, vector: np.ndarray, k: int = 6) -> List[Tuple[str, float, float]]:
        model = self.bundle["model"]
        names = self.bundle["feature_names"]
        importances = getattr(model, "feature_importances_", None)
        if importances is None:
            return []
        contrib = importances * np.abs(vector)
        order = np.argsort(contrib)[::-1]
        out: List[Tuple[str, float, float]] = []
        for i in order[:k]:
            if contrib[i] <= 0:
                continue
            out.append((names[i], float(vector[i]), float(importances[i])))
        return out

    def _scan_one_stream(self, data: bytes, filename: str) -> ScanResult:
        """Score exactly one byte stream, which is the behaviour every experiment uses."""
        vector, info = featurize(data)
        model = self.bundle["model"]
        prob = float(model.predict_proba(vector.reshape(1, -1))[0, 1])
        ml_verdict = "malicious" if prob >= 0.5 else "benign"

        rule = rule_scan(data)
        return ScanResult(
            filename=filename,
            size=len(data),
            ml_verdict=ml_verdict,
            ml_confidence=prob,
            rule_verdict=rule["verdict"],
            rule_reasons=rule["reasons"],
            imports=list(info["imports"]),
            suspicious_imports=list(info["suspicious_imports"]),
            opcodes=list(info["ops"]),
            parse_error=bool(info["parse_error"]),
            proto_version=int(info["proto_version"]),
            n_ops=int(info["n_ops"]),
            byte_tokens=list(info.get("byte_tokens", [])),
            nonallowlisted_globals=list(info.get("nonallowlisted_globals", [])),
            picklescan_dangerous=int(info.get("picklescan_dangerous", 0)),
            top_features=self._top_features(vector),
        )

    def scan_bytes(self, data: bytes, filename: str = "uploaded") -> ScanResult:
        """Score the main stream, then every extra pickle member of a container.

        The worst member decides the verdict, because an archive is only as safe as
        the most dangerous stream inside it. The returned result keeps the size of the
        whole upload, so the reported size is still the file the user handed over.
        """
        best = self._scan_one_stream(data, filename)
        members = archive_members(data)
        if not members:
            return best
        best.scanned_members = ["(main stream)"] + [n for n, _b in members]
        for name, blob in members:
            other = self._scan_one_stream(blob, filename)
            worse = (other.final_verdict == "malicious" and best.final_verdict != "malicious") or                     (other.final_verdict == best.final_verdict and other.ml_confidence > best.ml_confidence)
            if worse:
                members_seen, _ = best.scanned_members, None
                size = best.size
                best = other
                best.scanned_members = members_seen
                best.flagged_member = name
                best.size = size
        return best

    def scan_file(self, path: str) -> ScanResult:
        with open(path, "rb") as fh:
            data = fh.read()
        return self.scan_bytes(data, filename=os.path.basename(path))
