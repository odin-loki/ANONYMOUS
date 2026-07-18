# Adaptive guard mitigation (v1 + v2 + v3)

**Status:** partial sim + Rust hook (2026-07-18) — **does not close spec §13**

## Problem (quantified)

Long-horizon adaptive adversary exposure grows toward 1.0 even with a stable
guard set (`sim/data/adaptive_guard_exposure.analysis.json`). See
[`research_open_items.md`](research_open_items.md) §A.

## Mitigation tiers (in-tree)

| Layer | v1 (`mitigated_first` / `adaptive_first`) | v2 (`mitigated` / `adaptive_v2`) | v3 (`mitigated_v3` / `adaptive_v3`) |
|-------|-------------------------------------------|----------------------------------|-------------------------------------|
| **Sim sticky hard cap** | 10 epochs | 8 epochs (7 aggressive tier) | **4 epochs** |
| **Sim soft sticky / decay** | — | — | soft from age **2**, `stickiness_decay=0.62` |
| **Sim demotion** | decay 0.72, floor 0.15×c | decay 0.55, floor 0.10×c + 5-epoch linger | decay **0.40**, floor **0.05×c** + 10-epoch linger |
| **Sim reputation soft rotate** | — | — | `rep_signal_scale=0.45` (peer-health-like; not exposure) |
| **Sim aggressive tier** | — | extra 0.75× decay on dirty (`mitigated_aggressive`) | aggressive on dirty + rep demotion extra 0.88 |
| **Rust sticky hard cap** | 12 epochs | 8 epochs | **4 epochs** |
| **Rust soft sticky** | disabled (soft=hard) | disabled (soft=hard) | soft from age **2** (deterministic decay pressure) |
| **Rust peer spike** | threshold 2 | threshold 1 | threshold 1 |

| Layer | Mechanism |
|-------|-----------|
| **Sim** | `mode='mitigated_v3'` (best), `mode='mitigated'` (v2), `mode='mitigated_first'` (v1), `mode='mitigated_aggressive'` (v2 tier) in `adaptive_guard_exposure` |
| **Rust** | [`GuardMitigationPolicy`](../../crates/aegis-topology/src/guard_mitigation.rs) — presets `adaptive_first()`, `adaptive_v2()`, **`adaptive_v3()`** |
| **Trust** | [`peer_health_spike_detected`](../../crates/aegis-trust/src/policy.rs) — count threshold hook for topology |

Production defaults remain unchanged (`GuardMitigationPolicy::disabled()`).

### Why v3 (not “v2 remains best”)

Parameter sweeps (`sim/scripts/sweep_adaptive_mitigation.py`) showed hard epoch-age
caps + decaying stickiness + reputation-aware soft rotate dominate mid-horizon
exposure vs v2 sticky-only demotion. Locked preset maps cleanly onto client
`GuardMitigationPolicy` (hard cap, soft band, anomaly / peer-spike rotate).

### v3 mid-horizon result (honest)

At `c=0.015`, `g=3`, `E=200` (committed artifact, 15k trials):

- Unmitigated adaptive: ~1.0
- v1 (`mitigated_first`): ~0.90
- v2 (`mitigated`): ~0.77
- v2 aggressive: ~0.70
- **v3 (`mitigated_v3`): ~0.45** — **~32 pp lower than v2** at mid horizon

Long horizons still saturate toward 1.0 (E=800 ~0.86, E=2000 ~0.99).
**§13 remains [O] QUANTIFIED + Partial mitigation.**

## Enforcement point: **client**

Guard selection and path pinning happen on the **client** when building a bound
path (`GuardSelector` / `build_bound_path_pruned_with_guards_mitigated`). Relay
nodes parse `[guard_mitigation]` for operator symmetry but **do not** select
client paths.

### Client TOML (primary)

```toml
[guard_mitigation]
preset = "adaptive_v3"   # "adaptive_first" | "adaptive_v2" | "adaptive_v3"; omit = disabled

# Legacy (still supported when preset omitted):
# adaptive_first = true

[path]
epoch_age = 3            # pilot: epochs since last guard re-sample (v3 hard cap = 4)
anomaly_demotion_flag = false
peer_anomaly_count = 0
```

Parsed into [`GuardMitigationFileConfig`](../../crates/aegis-topology/src/guard_mitigation.rs)
and resolved to `GuardMitigationPolicy::adaptive_v3()` (hard sticky cap 4, soft
band from 2, rotate on anomaly / single peer-health spike), `adaptive_v2()`, or
`adaptive_first()` (legacy).

At path build time, the client CLI and library callers use [`build_client_bound_path`](../../crates/aegis-client/src/path.rs)
(or topology's `build_bound_path_pruned_with_guards_mitigated`) with:

1. **`GuardMitigationSignals`** — `epoch_age`, `anomaly_demotion_flag`,
   `peer_anomaly_count` from `[path]` when set (defaults zero/false when telemetry unavailable).
2. **`apply_to_config_with_signals`** — sets `GuardPinMode::Rotate` under signal.
3. **`client_seed_for_guards`** — re-mixes client seed when `should_resample_guards`.

When signals are absent, `adaptive_v3` still applies soft-band / hard-cap rotation
and rotate-on-anomaly / peer-spike thresholds once wired.

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

- Sim demotion / reputation soft signals are a **model**, not measured recompromise rate.
- v3 lowers mid-horizon exposure vs v2 but mitigated curves still approach 1.0 at long horizons — **[O]**.
- Roster paths require `[[hops]]` KEM registry entries (or live key fetch, not wired).
- Does not address combined active+intersection or operational C2 traces.

## Regenerate artifact + tests

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py --only adaptive
cd sim && PYTHONPATH=. python scripts/sweep_adaptive_mitigation.py          # CI + offline
cd sim && PYTHONPATH=. python scripts/sweep_adaptive_mitigation.py --ci-only
cd sim && PYTHONPATH=. pytest -q \
  tests/test_hardening.py::test_mitigated_v3_improves_mid_horizon_vs_v2 \
  tests/test_hardening.py::test_mitigated_v3_still_saturates_long_horizon \
  tests/test_hardening.py::test_adaptive_mitigation_param_sweep_ci_bound
```

Rust:

```bash
cargo test -p aegis-topology guard_mitigation
cargo test -p aegis-client guard_mitigation
cargo test -p aegis-client path::
cargo test -p aegis-client hops_resolve
cargo test -p aegis-node guard_mitigation
```
