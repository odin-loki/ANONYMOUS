# Adaptive guard mitigation (v1 + v2)

**Status:** partial sim + Rust hook (2026-07-18) — **does not close spec §13**

## Problem (quantified)

Long-horizon adaptive adversary exposure grows toward 1.0 even with a stable
guard set (`sim/data/adaptive_guard_exposure.analysis.json`). See
[`research_open_items.md`](research_open_items.md) §A.

## Mitigation tiers (in-tree)

| Layer | v1 (`mitigated_first` / `adaptive_first`) | v2 (`mitigated` / `adaptive_v2`) |
|-------|-------------------------------------------|----------------------------------|
| **Sim sticky cap** | 10 epochs | 8 epochs (7 aggressive tier) |
| **Sim demotion** | decay 0.72, floor 0.15×c | decay 0.55, floor 0.10×c + 5-epoch linger after dirty |
| **Sim aggressive tier** | — | extra 0.75× decay on dirty (`mode='mitigated_aggressive'`) |
| **Rust sticky cap** | 12 epochs | 8 epochs |
| **Rust peer spike** | threshold 2 | threshold 1 |

| Layer | Mechanism |
|-------|-----------|
| **Sim** | `mode='mitigated'` (v2), `mode='mitigated_first'` (v1 baseline), `mode='mitigated_aggressive'` (v2 second tier) in `adaptive_guard_exposure` |
| **Rust** | [`GuardMitigationPolicy`](../../crates/aegis-topology/src/guard_mitigation.rs) — presets `adaptive_first()`, `adaptive_v2()` |
| **Trust** | [`peer_health_spike_detected`](../../crates/aegis-trust/src/policy.rs) — count threshold hook for topology |

Production defaults remain unchanged (`GuardMitigationPolicy::disabled()`).

### v2 mid-horizon result (honest)

At `c=0.015`, `g=3`, `E=200` (20k trials, committed artifact):

- Unmitigated adaptive: ~1.0
- v1 (`mitigated_first`): ~0.90
- v2 (`mitigated`): ~0.77 — **~13 pp lower than v1** at mid horizon
- v2 aggressive: ~0.71

Long horizons still saturate toward 1.0. **§13 remains [O].**

## Enforcement point: **client**

Guard selection and path pinning happen on the **client** when building a bound
path (`GuardSelector` / `build_bound_path_pruned_with_guards_mitigated`). Relay
nodes parse `[guard_mitigation]` for operator symmetry but **do not** select
client paths.

### Client TOML (primary)

```toml
[guard_mitigation]
preset = "adaptive_v2"   # "adaptive_first" | "adaptive_v2"; omit = disabled

# Legacy (still supported when preset omitted):
# adaptive_first = true

[path]
epoch_age = 7            # pilot: epochs since last guard re-sample
anomaly_demotion_flag = false
peer_anomaly_count = 0
```

Parsed into [`GuardMitigationFileConfig`](../../crates/aegis-topology/src/guard_mitigation.rs)
and resolved to `GuardMitigationPolicy::adaptive_v2()` (sticky cap 8 epochs,
rotate on anomaly / single peer-health spike) or `adaptive_first()` (legacy).

At path build time, the client CLI and library callers use [`build_client_bound_path`](../../crates/aegis-client/src/path.rs)
(or topology's `build_bound_path_pruned_with_guards_mitigated`) with:

1. **`GuardMitigationSignals`** — `epoch_age`, `anomaly_demotion_flag`,
   `peer_anomaly_count` from `[path]` when set (defaults zero/false when telemetry unavailable).
2. **`apply_to_config_with_signals`** — sets `GuardPinMode::Rotate` under signal.
3. **`client_seed_for_guards`** — re-mixes client seed when `should_resample_guards`.

When signals are absent, `adaptive_v2` still applies sticky-cap rotation at
`epoch_age >= 8` and rotate-on-anomaly / peer-spike thresholds once wired.

**CLI:** with `[roster]` configured, omit ordered `[[hops]]` (or pass `--roster-path`) to
build a mitigated bound path; explicit `[[hops]]` remains the pilot/lab override. KEM
registry entries keyed by relay `id` are required for roster paths.

### Node TOML (operator symmetry)

The same `[guard_mitigation]` section is accepted on node configs (parsed into
`NodeRuntimeConfig.guard_mitigation`) so pilot/production templates stay aligned.
It is **not** consumed on the relay datapath today — clients enforce the policy.

Pilot templates include a commented example; production template:
`deploy/templates/node.production.toml`.

## Honest limits

- Sim demotion is a **model**, not measured recompromise rate.
- v2 lowers mid-horizon exposure vs v1 but mitigated curves still approach 1.0 at long horizons — **[O]**.
- Roster paths require `[[hops]]` KEM registry entries (or live key fetch, not wired).
- Does not address combined active+intersection or operational C2 traces.

## Regenerate artifact + tests

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py
cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py::test_mitigated_v2_improves_mid_horizon_vs_v1_baseline
```

Rust:

```bash
cargo test -p aegis-topology guard_mitigation
cargo test -p aegis-client guard_mitigation
cargo test -p aegis-client path::
cargo test -p aegis-client hops_resolve
cargo test -p aegis-node guard_mitigation
```
