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
    exit_tier_intersection
                 - multi-client exit window anonymity-set / intersection (C2; not WAN closed)
    exit_tier_defense
                 - wave S4: exit-window pad / decoy defenses ranked vs tip-intersection + volume rank
    cover_multihop_defense
                 - wave S4: cover onions / matched discard ranked vs multi-hop semantic gap
    metrics_scrape_defense
                 - wave A5: cadence / quantize / suppress-drops ranked vs C5 scrape Pearson
    fused_adversary
                 - adaptive recompromise ∩ Mode-1 active/intersection coupling (C2)
    faction_sybil_skew
                 - M-of-N faction / jurisdiction-skew roster admission (wave C3)
    ac_nullifier_unlinkability
                 - wave C4 lab: issuer correlation, double-spend, merge_from_file eclipse
    gossip_eclipse
                 - wave C1: gossip eclipse + majority_k collusion ([O] QUANTIFIED Partial)
    gossip_eclipse_defense
                 - wave S5: raised-K / org-diversity / eclipse-detect vs C1 baseline
    fused_defense
                 - wave S5: adaptive_v4 + fused Mode-1 hard_cap under recompromise
    sphinx_oracle
                 - wave S1: bit-level Sphinx build/peel/MAC/replay oracle (KEM Rust-only;
                   not a formal proof)
    metrics      - anonymity metrics (matching accuracy, disclosure, Hurst),
                   plus (Phase 8) shapeability_report for honest per-trace tiering

The regression suite in ../tests/test_evidence_ledger.py pins the evidence-ledger
results so that any future change that weakens a defense fails a test.
../tests/test_hardening.py characterizes (does not close) the Phase 8 open items
from spec §13: real-trace shapeability, adaptive compromised-mix set, and
combined active+intersection long-horizon attacks.
"""
__all__ = [
    "traffic",
    "shaper",
    "adversaries",
    "combined_active_intersection",
    "exit_tier_intersection",
    "exit_tier_defense",
    "cover_multihop_defense",
    "metrics_scrape_defense",
    "fused_adversary",
    "faction_sybil_skew",
    "ac_nullifier_unlinkability",
    "gossip_eclipse",
    "gossip_eclipse_defense",
    "fused_defense",
    "sphinx_oracle",
    "metrics",
]
