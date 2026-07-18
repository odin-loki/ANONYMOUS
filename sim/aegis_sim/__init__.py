"""
aegis_sim: reusable traffic-analysis simulation core for AEGIS.

Extracted and consolidated from the red-team attack scripts (see ../attacks/).
The design decisions these validate live in ../../docs/AEGIS_SPEC_v3_consolidated.md.

Modules:
    traffic      - Gaussian and non-Gaussian (heavy-tailed / self-similar) generators,
                   plus (Phase 8) real-trace ingestion + a synthetic C2-like stand-in
    shaper       - constant-rate hard-cap shaper (the core Mode-1 defense)
    adversaries  - timing, volume, intersection, confirmation, bulk attacks,
                   plus (Phase 8) an adaptive compromised-mix-set adversary
    combined_active_intersection
                 - fused active(n-1)+intersection ranking, sensitivity, offline horizons
    metrics      - anonymity metrics (matching accuracy, disclosure, Hurst),
                   plus (Phase 8) shapeability_report for honest per-trace tiering

The regression suite in ../tests/test_evidence_ledger.py pins the evidence-ledger
results so that any future change that weakens a defense fails a test.
../tests/test_hardening.py characterizes (does not close) the Phase 8 open items
from spec §13: real-trace shapeability, adaptive compromised-mix set, and
combined active+intersection long-horizon attacks.
"""
__all__ = ["traffic", "shaper", "adversaries", "combined_active_intersection", "metrics"]
