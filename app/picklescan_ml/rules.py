"""A simple rule-based scanner used as the baseline.

This mirrors the idea behind picklescan and ModelScan. It reads the imports a
pickle performs and raises an alarm when it sees a known dangerous module or a
known dangerous (module, name) pair. It is intentionally a denylist, so it can
be fooled by any trick that hides a dangerous import, which is exactly the
weakness this project measures.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from .features import extract_imports, extract_ops, SUSPICIOUS_MODULES

# Dangerous (module, name) pairs that should never appear in a clean model file.
DANGEROUS_PAIRS = {
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"),
    ("os", "spawnl"), ("os", "spawnv"), ("nt", "system"), ("posix", "system"),
    ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "run"),
    ("subprocess", "check_output"), ("subprocess", "check_call"),
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "compile"),
    ("builtins", "__import__"), ("builtins", "getattr"), ("builtins", "setattr"),
    ("__builtin__", "eval"), ("__builtin__", "exec"), ("__builtin__", "execfile"),
    ("importlib", "import_module"), ("runpy", "_run_code"),
    ("pty", "spawn"), ("code", "interact"),
    ("socket", "socket"), ("base64", "b64decode"), ("codecs", "decode"),
    ("webbrowser", "open"),
}

# Modules that are dangerous on their own.
DANGEROUS_MODULES = set(SUSPICIOUS_MODULES)


def _bounded(data: bytes):
    """Unwrap and cap the stream so a baseline tool cannot be driven into a hang
    by an oversized or zip-bomb input. Returns None when the stream is too large
    to scan safely, in which case the caller reports no verdict."""
    from .features import MAX_DEEP_SCAN_BYTES, unwrap
    inner = unwrap(data)
    return None if len(inner) > MAX_DEEP_SCAN_BYTES else inner


def real_picklescan(data: bytes) -> bool:
    """Verdict from the actual picklescan tool, used as an industry baseline.
    Returns True when picklescan reports at least one dangerous global."""
    try:
        import io
        import picklescan.scanner as ps
        inner = _bounded(data)
        if inner is None:
            return False
        res = ps.scan_bytes(io.BytesIO(inner), "x")
        return int(getattr(res, "issues_count", 0) or 0) > 0
    except Exception:
        return False


def real_modelscan(data: bytes) -> bool:
    """Verdict from Protect AI's ModelScan tool, a second denylist baseline.
    Returns True when ModelScan reports at least one issue. It scans a path, so
    the bytes are written to a temporary file and analysed statically."""
    try:
        import os
        import tempfile
        from modelscan.modelscan import ModelScan
        data = _bounded(data)
        if data is None:
            return False
        fd, path = tempfile.mkstemp(suffix=".pkl")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            res = ModelScan().scan(path)
            return int(res.get("summary", {}).get("total_issues", 0) or 0) > 0
        finally:
            os.remove(path)
    except Exception:
        return False


def real_fickling(data: bytes) -> bool:
    """Verdict from Trail of Bits' fickling tool, a third denylist baseline.
    Returns True when fickling judges the pickle not likely safe. This mirrors
    fickling.is_likely_safe exactly but reads from bytes in memory rather than a
    path, so no file is written and nothing is ever loaded."""
    import io

    from fickling.analysis import Severity, check_safety
    from fickling.fickle import Pickled
    try:
        inner = _bounded(data)
        if inner is None:
            return False
        pickled = Pickled.load(io.BytesIO(inner), fail_on_decode_error=False)
        if pickled.has_invalid_opcode:
            return True   # a broken or invalid stream is treated as not safe
        return check_safety(pickled).severity != Severity.LIKELY_SAFE
    except Exception:
        # fickling could not analyse the stream at all, so it gives no verdict.
        return False


def rule_scan(data: bytes) -> Dict[str, object]:
    """Scan a pickle and return a verdict in the same shape the ML path uses."""
    from .features import MAX_STREAM_BYTES, unwrap
    data = unwrap(data)
    # A stream past the size cap is never opcode-scanned, so no evidence can be
    # gathered either way. Chapter 5 recommends treating an unreadable file as
    # suspicious rather than clean, so we say so instead of silently passing it.
    if len(data) > MAX_STREAM_BYTES:
        return {
            "verdict": "suspicious",
            "malicious": False,
            "reasons": ["Stream exceeds the safe scan limit, so it was not analysed"],
            "imports": [],
            "parse_error": True,
        }
    ops, parse_error = extract_ops(data)
    imports = extract_imports(ops)
    reasons: List[str] = []

    for module, name in imports:
        if (module, name) in DANGEROUS_PAIRS:
            reasons.append(f"Dangerous import {module}.{name}")
        elif module in DANGEROUS_MODULES:
            reasons.append(f"Suspicious module {module} imported as {module}.{name}")

    has_reduce = any(op[0] == "REDUCE" for op in ops)
    has_dangerous_import = len(reasons) > 0

    # A REDUCE on top of a dangerous import is the classic run-code pattern.
    malicious = has_dangerous_import and has_reduce
    # If a dangerous import is present but no REDUCE was seen, flag as suspicious.
    suspicious = has_dangerous_import and not has_reduce

    if parse_error:
        reasons.append("Stream could not be fully parsed")

    verdict = "malicious" if malicious else ("suspicious" if suspicious else "benign")
    return {
        "verdict": verdict,
        "malicious": malicious,
        "reasons": reasons,
        "imports": imports,
        "parse_error": parse_error,
    }
