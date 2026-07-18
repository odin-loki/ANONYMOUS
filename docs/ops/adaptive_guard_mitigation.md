# Adaptive guard mitigation (first pass)

**Status:** partial sim + Rust hook (2026-07-18) — **does not close spec §13**

## Problem (quantified)

Long-horizon adaptive adversary exposure grows toward 1.0 even with a stable
guard set (`sim/data/adaptive_guard_exposure.analysis.json`). See
[`research_open_items.md`](research_open_items.md) §A.

## First mitigation (in-tree)

| Layer | Mechanism |
|-------|-----------|
| **Sim** | `mode='mitigated'` in `adaptive_guard_exposure` — sticky cap + re-sample on dirty epoch + effective `c` demotion |
| **Rust** | [`GuardMitigationPolicy`](../../crates/aegis-topology/src/guard_mitigation.rs) — `should_resample_guards`, `pin_mode_for_epoch`, preset `adaptive_first()` |
| **Trust** | [`peer_health_spike_detected`](../../crates/aegis-trust/src/policy.rs) — count threshold hook for topology |

Production defaults remain unchanged (`GuardMitigationPolicy::disabled()`).

## Operator wiring (future)

1. Feed peer metrics via `feed_peer_outcomes` / `RelayPruningPolicy::observe_metric`.
2. On epoch tick, if `GuardMitigationPolicy::should_resample_guards(...)` →
   `GuardSelector::new_reputation_weighted_pruned` with fresh client seed.
3. Apply `pin_mode_for_epoch` when building paths (`GuardPinMode::Rotate` under signal).

## Honest limits

- Sim demotion is a **model**, not measured recompromise rate.
- Mitigated curve is **lower** than unmitigated adaptive at long horizons; still **[O]**.
- Does not address combined active+intersection or operational C2 traces.

## Regenerate artifact + tests

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py
cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py::test_mitigated_adaptive_exposure_lower_than_unmitigated
```
