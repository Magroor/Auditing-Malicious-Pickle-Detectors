"""picklecore: static, monotonicity-safe analysis of pickle model files.

Modules
-------
asm          hand assembly of pickle byte streams (never loads malicious bytes)
semantic_ref reference abstract machine + canonical emission (PROOFS.md s.0-1)
core         monotone core (C2-v0) + non-monotone windowed control
baselines    faithful SafePickle reproduction (SP-RF/SP-CB) and the v1-style baseline
attacks      A1/A1b/A2/A3/A9 insertion families with a static Phi check
eval_dev     grouped-fold evaluation, non-inferiority, robustness, fuzz tests
corpus       synthetic pilot corpus (harmless echo payloads, never executed)
"""
__all__ = ["asm", "semantic_ref", "core", "baselines", "attacks", "eval_dev", "corpus"]
