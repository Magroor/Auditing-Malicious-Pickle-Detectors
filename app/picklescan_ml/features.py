"""Static feature extraction from pickle streams.

Everything here is read-only. We use pickletools.genops, which walks the pickle
opcodes one by one without ever executing them. A malicious file is therefore
safe to analyse with this module because the payload is never run.
"""

from __future__ import annotations

import io
import pickletools
from typing import Dict, List, Tuple

import numpy as np

# Fixed opcode vocabulary, taken from the Python pickle machine itself so the
# feature order is stable across runs and machines.
OPCODE_NAMES: List[str] = sorted({op.name for op in pickletools.opcodes})
OPCODE_INDEX: Dict[str, int] = {name: i for i, name in enumerate(OPCODE_NAMES)}

# Opcodes that produce a string value on the stack. We track their arguments so
# that a STACK_GLOBAL can be paired with the module and name pushed before it.
STRING_OPCODES = {
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
    "SHORT_BINSTRING", "BINSTRING", "STRING",
}

# Opcodes that can import or call Python objects. These are the heart of the
# danger in a pickle file.
CALL_OPCODES = {"REDUCE", "GLOBAL", "STACK_GLOBAL", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD", "EXT1", "EXT2", "EXT4"}

# Modules that almost never appear in a legitimate model file and are a strong
# signal of an attempt to run code.
SUSPICIOUS_MODULES = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty",
    "importlib", "runpy", "code", "pdb", "bdb", "commands", "popen2",
    "ctypes", "webbrowser", "requests", "urllib", "smtplib",
}

# Dangerous name tokens that we look for directly in the RAW bytes, not only in
# the parsed opcodes. This matters because a truncation trick, such as the real
# nullifAI broken stream, can stop the opcode parser early while the dangerous
# name is still sitting in the bytes. Each token below was checked to give zero
# false positives on benign model files.
DANGEROUS_TOKENS = [
    b"system", b"subprocess", b"Popen", b"popen", b"eval", b"exec",
    b"posix", b"commands", b"runpy", b"pty", b"socket", b"__reduce__",
    b"importlib", b"__import__", b"getattr", b"check_output", b"builtins",
    b"pydoc", b"operator", b"pipepager", b"methodcaller", b"partial",
    # Real-world payload indicators seen in genuine malicious model files, such as
    # reverse shells, credential stealers and exfiltration gadgets. Each is rare in
    # a legitimate model file, so it raises detection on real malware without
    # hurting the clean record. Synthetic files do not contain any of these, so the
    # synthetic results are unaffected.
    b"base64", b"b64decode", b"marshal", b"ctypes", b"/bin/sh",
    b"/bin/bash", b"bash -i", b"dup2", b"AF_INET", b"SOCK_STREAM",
    b"execve", b"setsid", b"cmd.exe", b"powershell", b"urlretrieve",
    b"urlopen", b"/dev/tcp", b"webbrowser",
]

# Optional robust global extractor from the real picklescan tool. When present
# it parses the stream far more carefully than the local reader.
try:
    import picklescan.scanner as _PICKLESCAN
except Exception:  # pragma: no cover
    _PICKLESCAN = None

# Allowlist of module prefixes that legitimate model files import. Any import
# outside this set is treated as non-allowlisted. This is the key defence
# against novel code-execution gadgets that a denylist has never seen, because
# a benign model never needs os, subprocess, pydoc, operator and the like.
SAFE_MODULE_PREFIXES = (
    "numpy", "scipy", "sklearn", "pandas", "collections", "copyreg",
    "copy_reg", "_codecs", "joblib", "torch", "xgboost", "lightgbm",
    "torchvision", "PIL", "keras", "tensorflow",
    # Real machine-learning ecosystem modules that legitimate Hugging Face
    # checkpoints import. Added so the allowlist does not false-positive on real
    # models. These are safe ML libraries, not code-execution modules such as os
    # or subprocess, so the danger signal is unchanged. Synthetic benign files do
    # not use any of these, so the synthetic results are unaffected.
    "transformers", "tokenizers", "safetensors", "huggingface_hub",
    "accelerate", "datasets", "sentencepiece", "timm", "diffusers",
    "einops", "gymnasium", "gym", "cloudpickle", "catboost",
)
SAFE_BUILTIN_NAMES = {
    "object", "list", "dict", "set", "tuple", "frozenset", "bytearray",
    "complex", "bytes", "int", "float", "str", "bool", "slice",
}


def _is_allowlisted(module: str, name: str) -> bool:
    if module.startswith(SAFE_MODULE_PREFIXES):
        return True
    if module in ("builtins", "__builtin__"):
        return name in SAFE_BUILTIN_NAMES
    return False


def robust_globals(data: bytes, ops):
    """Return the (module, name) globals a pickle imports plus the picklescan
    dangerous count. Uses the real picklescan parser when available and falls
    back to the local opcode reader for broken streams."""
    ps_dangerous = 0
    # Skip the heavier picklescan re-parse on oversized streams and on anything
    # still in a ZIP container, so it cannot be tricked into expanding a bomb.
    if _PICKLESCAN is not None and len(data) <= MAX_DEEP_SCAN_BYTES and data[:2] != b"PK":
        try:
            res = _PICKLESCAN.scan_bytes(io.BytesIO(data), "x")
            ps_dangerous = int(getattr(res, "issues_count", 0) or 0)
            globs = [(g.module, g.name) for g in getattr(res, "globals", [])]
            if globs:
                return globs, ps_dangerous
        except Exception:
            pass
    return extract_imports(ops), ps_dangerous

# Hand-picked suspicious opcode bigrams. A learned model still sees the full
# histogram, but these named bigrams make the feature vector interpretable.
SUSPICIOUS_BIGRAMS = [
    ("GLOBAL", "REDUCE"),
    ("STACK_GLOBAL", "REDUCE"),
    ("GLOBAL", "TUPLE"),
    ("STACK_GLOBAL", "TUPLE1"),
    ("GLOBAL", "INST"),
    ("BINUNICODE", "STACK_GLOBAL"),
    ("SHORT_BINUNICODE", "STACK_GLOBAL"),
    ("REDUCE", "BUILD"),
]


# Hard ceilings so a hostile upload cannot exhaust memory or CPU. A real model
# keeps its tensors in separate archive members, so a genuine data.pkl is far
# smaller than these limits. Anything larger is treated as unparseable, which is
# the safe default this project already recommends for streams it cannot read.
MAX_STREAM_BYTES = 16 * 1024 * 1024      # read opcodes from at most 16 MB
MAX_OPS = 1_000_000                      # stop after this many opcodes
MAX_DEEP_SCAN_BYTES = 4 * 1024 * 1024    # run the heavier picklescan re-parse only up to 4 MB


def unwrap(data: bytes) -> bytes:
    """Return the inner pickle stream from a container.

    Modern torch.save writes a ZIP archive whose data lives in an inner
    data.pkl. Real model files are therefore ZIP-wrapped, so a scanner that
    reads raw bytes would miss the payload entirely. This unwraps the ZIP and
    returns the inner pickle so the rest of the pipeline sees the real stream.
    """
    if data[:2] == b"PK":
        try:
            import zipfile
            z = zipfile.ZipFile(io.BytesIO(data))
            names = z.namelist()
            pkls = [n for n in names if n.endswith("data.pkl")] or [n for n in names if n.endswith(".pkl")]
            if pkls:
                # Read the inner member incrementally and stop after the cap, so a
                # zip bomb cannot expand a tiny upload into gigabytes of memory.
                # A real data.pkl is far smaller than the cap, so nothing is lost.
                with z.open(pkls[0]) as fh:
                    return fh.read(MAX_STREAM_BYTES + 1)
        except Exception:
            pass
    return data


# Opcodes that push exactly one value while consuming nothing from the stack. When one of
# these is immediately discarded by a POP, the pair is provably inert, so an adaptive attacker
# can inject unlimited copies to pad the opcode stream and push the real payload out of a
# fixed-window model. We cancel such inert pairs before any feature is read.
_NULLARY_PUSH = frozenset({
    "EMPTY_LIST", "EMPTY_DICT", "EMPTY_TUPLE", "EMPTY_SET", "NONE", "NEWTRUE", "NEWFALSE",
    "BININT", "BININT1", "BININT2", "LONG1", "LONG4", "BINFLOAT",
    "SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8",
    "SHORT_BINBYTES", "BINBYTES", "BINBYTES8", "SHORT_BINSTRING", "BINSTRING",
})


def canonicalize_ops(ops: List[Tuple[str, object, int]]) -> List[Tuple[str, object, int]]:
    """Remove provably-inert opcode pairs, a nullary push immediately discarded by a POP, or a
    MARK immediately closed by a POP_MARK. This is a normalisation for analysis only, it never
    executes the pickle. It defeats the opcode-padding evasion, because the attacker's no-op
    blocks cancel here so the real payload returns to the front of the stream, while a normal
    pickle is untouched since it does not push a value only to throw it away.

    The cancellation is done in a single stack pass, which is linear in the number of opcodes.
    A repeated sweep-until-nothing-changes would give the same answer, because no two cancelling
    pairs can overlap, since POP and POP_MARK are never themselves a nullary push and MARK is
    not one either, therefore the rewriting has one normal form. The sweep would however be
    quadratic on nested padding such as a run of pushes closed by a run of pops, which an
    adaptive attacker can write in a few kilobytes, so the single pass is used instead."""
    out: List[Tuple[str, object, int]] = []
    for op in ops:
        b = op[0]
        if out:
            a = out[-1][0]
            if (b == "POP" and a in _NULLARY_PUSH) or (b == "POP_MARK" and a == "MARK"):
                out.pop()
                continue
        out.append(op)
    return out


def extract_ops(data: bytes) -> Tuple[List[Tuple[str, object, int]], bool]:
    """Disassemble a pickle into a list of (opcode_name, arg, position).

    Returns the list together with a parse_error flag that is True when the
    stream could not be fully parsed, which is itself a useful signal because
    several real evasion tricks rely on broken or truncated streams. The opcode
    list is canonicalised to cancel inert padding, so an opcode-space padding
    attack cannot hide the payload behind a wall of no-ops.
    """
    ops: List[Tuple[str, object, int]] = []
    parse_error = False
    if not data:
        return ops, True
    if len(data) > MAX_STREAM_BYTES:
        # An oversized stream is treated as unparseable rather than scanned, so
        # an opcode flood or a STOP flood cannot exhaust memory or time.
        return ops, True
    try:
        for opcode, arg, pos in pickletools.genops(data):
            ops.append((opcode.name, arg, pos))
            if len(ops) >= MAX_OPS:
                # A stream that packs more opcodes than any real model is capped
                # here and flagged, which stops a single-byte-opcode flood.
                parse_error = True
                break
    except Exception:
        # Truncated, malformed or deliberately broken stream. We keep whatever
        # opcodes were read before the failure.
        parse_error = True
    return canonicalize_ops(ops), parse_error


def extract_imports(ops: List[Tuple[str, object, int]]) -> List[Tuple[str, str]]:
    """Recover the (module, name) targets that the pickle imports.

    GLOBAL carries its target inside the argument. STACK_GLOBAL takes the module
    and name from the two string values pushed just before it.
    """
    imports: List[Tuple[str, str]] = []
    recent_strings: List[str] = []
    for name, arg, _pos in ops:
        if name in STRING_OPCODES and isinstance(arg, str):
            recent_strings.append(arg)
            if len(recent_strings) > 8:
                recent_strings.pop(0)
        elif name == "GLOBAL" and isinstance(arg, str):
            parts = arg.replace("\n", " ").split()
            if len(parts) >= 2:
                imports.append((parts[0], parts[1]))
            elif len(parts) == 1:
                imports.append((parts[0], ""))
        elif name == "STACK_GLOBAL":
            if len(recent_strings) >= 2:
                module, attr = recent_strings[-2], recent_strings[-1]
                imports.append((module, attr))
    return imports


# Build the full ordered feature-name list once.
def _build_feature_names() -> List[str]:
    names: List[str] = [f"op_{n}" for n in OPCODE_NAMES]
    names += [f"bigram_{a}_{b}" for a, b in SUSPICIOUS_BIGRAMS]
    names += [
        "n_ops",
        "stream_len",
        "n_distinct_ops",
        "proto_version",
        "has_reduce",
        "n_reduce",
        "has_global",
        "n_global",
        "has_stack_global",
        "n_imports",
        "n_suspicious_imports",
        "n_strings",
        "max_string_len",
        "parse_error",
        "ops_per_byte",
        "n_byte_tokens",
        "has_byte_token",
        "n_nonallowlisted_globals",
        "has_nonallowlisted_global",
        "picklescan_dangerous",
    ]
    return names


FEATURE_NAMES: List[str] = _build_feature_names()


def featurize(data: bytes) -> Tuple[np.ndarray, Dict[str, object]]:
    """Turn a pickle byte string into a fixed-length numeric feature vector.

    Returns the vector and an info dictionary used by the user interface to
    explain a verdict.
    """
    data = unwrap(data)
    ops, parse_error = extract_ops(data)

    hist = np.zeros(len(OPCODE_NAMES), dtype=np.float32)
    op_sequence: List[str] = []
    string_lengths: List[int] = []
    proto_version = 0
    for name, arg, _pos in ops:
        idx = OPCODE_INDEX.get(name)
        if idx is not None:
            hist[idx] += 1.0
        op_sequence.append(name)
        if name == "PROTO" and isinstance(arg, int):
            proto_version = max(proto_version, arg)
        if name in STRING_OPCODES and isinstance(arg, str):
            string_lengths.append(len(arg))

    # Suspicious bigram counts.
    bigram_counts = np.zeros(len(SUSPICIOUS_BIGRAMS), dtype=np.float32)
    seq_pairs = list(zip(op_sequence, op_sequence[1:]))
    for bi, pair in enumerate(SUSPICIOUS_BIGRAMS):
        bigram_counts[bi] = float(seq_pairs.count(pair))

    imports = extract_imports(ops)
    n_suspicious = sum(1 for m, _ in imports if m in SUSPICIOUS_MODULES)

    # Raw-byte token scan. This does not depend on a clean parse, so it still
    # fires on a truncated or broken stream.
    byte_tokens = [tok for tok in DANGEROUS_TOKENS if tok in data[:MAX_STREAM_BYTES]]
    n_byte_tokens = len(byte_tokens)

    # Allowlist signals. Any import outside the safe ML-library set is a strong
    # sign of a code-execution gadget, including novel ones a denylist misses.
    globs, ps_dangerous = robust_globals(data, ops)
    nonallow = [(m, n) for m, n in globs if not _is_allowlisted(m, n)]
    n_nonallowlisted = len(nonallow)

    n_ops = float(len(ops))
    stream_len = float(len(data))
    structural = np.array([
        n_ops,
        stream_len,
        float(len(set(op_sequence))),
        float(proto_version),
        1.0 if "REDUCE" in op_sequence else 0.0,
        float(op_sequence.count("REDUCE")),
        1.0 if "GLOBAL" in op_sequence else 0.0,
        float(op_sequence.count("GLOBAL")),
        1.0 if "STACK_GLOBAL" in op_sequence else 0.0,
        float(len(imports)),
        float(n_suspicious),
        float(len(string_lengths)),
        float(max(string_lengths) if string_lengths else 0),
        1.0 if parse_error else 0.0,
        (n_ops / stream_len) if stream_len > 0 else 0.0,
        float(n_byte_tokens),
        1.0 if n_byte_tokens > 0 else 0.0,
        float(n_nonallowlisted),
        1.0 if n_nonallowlisted > 0 else 0.0,
        float(ps_dangerous),
    ], dtype=np.float32)

    vector = np.concatenate([hist, bigram_counts, structural]).astype(np.float32)

    info: Dict[str, object] = {
        "ops": ops,
        "n_ops": int(n_ops),
        "stream_len": int(stream_len),
        "proto_version": int(proto_version),
        "imports": imports,
        "suspicious_imports": [(m, n) for m, n in imports if m in SUSPICIOUS_MODULES],
        "parse_error": parse_error,
        "has_reduce": "REDUCE" in op_sequence,
        "byte_tokens": [t.decode("latin-1") for t in byte_tokens],
        "nonallowlisted_globals": nonallow,
        "picklescan_dangerous": int(ps_dangerous),
    }
    return vector, info


def featurize_batch(blobs: List[bytes]) -> np.ndarray:
    """Featurize a list of byte strings into a 2D array."""
    if not blobs:
        return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32)
    return np.vstack([featurize(b)[0] for b in blobs])
