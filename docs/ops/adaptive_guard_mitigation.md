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
| **Rust** | [`GuardMitigationPolicy`](../../crates/aegis-topology/src/guard_mitigation.rs) — `should_resample_guards`, `pin_mode_for_epoch`, `apply_to_config`, preset `adaptive_first()` |
| **Trust** | [`peer_health_spike_detected`](../../crates/aegis-trust/src/policy.rs) — count threshold hook for topology |

Production defaults remain unchanged (`GuardMitigationPolicy::disabled()`).

## Enforcement point: **client**

Guard selection and path pinning happen on the **client** when building a bound
path (`GuardSelector` / `build_bound_path_pruned_with_guards_mitigated`). Relay
nodes parse `[guard_mitigation]` for operator symmetry but **do not** select
client paths.

### Client TOML (primary)

```toml
[guard_mitigation]
adaptive_first = true   # default false when section omitted
```

Parsed into [`GuardMitigationFileConfig`](../../crates/aegis-topology/src/guard_mitigation.rs)
and resolved to `GuardMitigationPolicy::adaptive_first()` (sticky cap 12 epochs,
rotate on anomaly / peer-health spike).

At path build time, use [`build_client_bound_path`](../../crates/aegis-client/src/path.rs)
(or topology's `build_bound_path_pruned_with_guards_mitigated`) with:

1. **`GuardMitigationSignals`** — `epoch_age`, `anomaly_demotion_flag`,
   `peer_anomaly_count` (defaults all zero/false when telemetry unavailable).
2. **`apply_to_config_with_signals`** — sets `GuardPinMode::Rotate` under signal.
3. **`client_seed_for_guards`** — re-mixes client seed when `should_resample_guards`.

When signals are absent, `adaptive_first` still applies sticky-cap rotation at
`epoch_age >= 12` and rotate-on-anomaly / peer-spike thresholds once wired.

### Node TOML (operator symmetry)

The same `[guard_mitigation]` section is accepted on node configs (parsed into
`NodeRuntimeConfig.guard_mitigation`) so pilot/production templates stay aligned.
It is **not** consumed on the relay datapath today — clients enforce the policy.

Pilot templates include a commented example; production template:
`deploy/templates/node.production.toml`.

## Honest limits

- Sim demotion is a **model**, not measured recompromise rate.
- Mitigated curve is **lower** than unmitigated adaptive at long horizons; still **[O]**.
- Client CLI with explicit hop lists does not yet auto-build roster paths; mitigation
  applies when callers use `build_client_bound_path`.
- Does not address combined active+intersection or operational C2 traces.

## Regenerate artifact + tests

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py
cd sim && PYTHONPATH=. pytest -q tests/test_hardening.py::test_mitigated_adaptive_exposure_lower_than_unmitigated
```

Rust:

```bash
cargo test -p aegis-topology guard_mitigation
cargo test -p aegis-client guard_mitigation
cargo test -p aegis-client path::
cargo test -p aegis-node guard_mitigation
```
