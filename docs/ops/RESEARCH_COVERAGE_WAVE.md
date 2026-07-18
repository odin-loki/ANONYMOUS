# Research coverage wave (no Docker)

**Date:** 2026-07-18  
**Tip baseline:** 649c4a7 → this wave  
**Goal:** Comprehensive in-repo research profiling of thin Partial/[O] surfaces.  
**Out of scope:** Docker, false “research closed”, inventing operational C2.  
**Status:** C1–C6 landed as **[O] QUANTIFIED / Partial** — not science-closed.

| ID | Track | In-repo deliverable | Key result | Honest leftover |
|----|-------|---------------------|------------|-----------------|
| C1 | Gossip eclipse / majority_k | `gossip_eclipse.py` + artifacts + 12 tests | f=0.25/K=3 bias≈0.45 FP≈1; f≥0.5 eclipse | Multi-org BFT |
| C2 | Exit-tier + fused adversary | `exit_tier_*` / `fused_adversary` + 15 tests | Exit tip-∩ →1 by E≈200; fused union→1 by E≈100 | WAN GPA |
| C3 | Faction / Sybil jurisdiction skew | `faction_sybil_skew.py` + 10 tests | Admit 0 if keys&lt;M else 1; skew concentrates exits | Legal governance |
| C4 | AC / nullifier unlinkability | `ac_nullifier_*` + 9 tests + Rust partition | Composite residual ≈0.86; local DS=0 | Interactive ZK |
| C5 | Cover multi-hop + metrics scrape | `cover_multihop` / `metrics_sidechannel` + 12 tests | Continuity ~0.44 vs 1.0; scrape Pearson≈0.97 | Info-theoretic cover |
| C6 | dudect WSL deepen | Lab deepen scripts + evidence | ~8×10⁷ / ~1×10⁶ traces on WSL | Isolated ≥10⁵ bar **not** met |

## Regenerate / test

```bash
cd sim && PYTHONPATH=. pytest -q \
  tests/test_gossip_eclipse.py \
  tests/test_exit_tier_intersection.py tests/test_fused_adversary.py \
  tests/test_faction_sybil_skew.py \
  tests/test_ac_nullifier_unlinkability.py \
  tests/test_cover_multihop.py tests/test_metrics_sidechannel.py

# dudect deepen (WSL, long):
# powershell -File scripts/run_dudect_lab_wsl.ps1 -Mode deepen
```

**Execution:** Grok 4.5 agents in parallel; parent integrates.
