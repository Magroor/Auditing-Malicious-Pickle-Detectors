"""picklescan_ml

A small, safe, static detector for malicious serialized machine learning models
that use the Python pickle format.

Design rule that must never be broken: this package never calls pickle.load or
pickle.loads on untrusted data. Every file is read only as opcodes through
pickletools, which disassembles the stream without executing it.
"""

from .features import featurize, extract_ops, extract_imports, FEATURE_NAMES
from .rules import rule_scan, DANGEROUS_PAIRS, DANGEROUS_MODULES
from .scan import Scanner, ScanResult

__all__ = [
    "featurize",
    "extract_ops",
    "extract_imports",
    "FEATURE_NAMES",
    "rule_scan",
    "DANGEROUS_PAIRS",
    "DANGEROUS_MODULES",
    "Scanner",
    "ScanResult",
]

__version__ = "1.0.0"
