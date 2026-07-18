# Adaptive guard mitigation (v1 + v2 + v3 + v4)

**Tip:** `c7c2f0d` · **Status:** partial sim + Rust hook (2026-07-18) — **does not close spec §13**  
**Theory:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md) §2.3 · preferred product preset: **`adaptive_v4`**

## Problem (quantified)

Long-horizon adaptive adversary exposure grows toward 1.0 even with a stable
guard set (`sim/data/adaptive_guard_exposure.analysis.json`). See
[`research_open_items.md`](research_open_items.md) §A.

## Mitigation tiers (in-tree)

| Layer | v1 (`mitigated_first` / `adaptive_first`) | v2 (`mitigated` / `adaptive_v2`) | v3 (`mitigated_v3` / `adaptive_v3`) | v4 (`mitigated_v4` / `adaptive_v4`) |
|-------|-------------------------------------------|----------------------------------|-------------------------------------|-------------------------------------|
| **Sim sticky hard cap** | 10 epochs | 8 epochs (7 aggressive tier) | **4 epochs** | **2 epochs** |
| **Sim soft sticky / decay** | — | — | soft from age **2**, `stickiness_decay=0.62` | soft from age **1**, `stickiness_decay=0.40` |
| **Sim demotion** | decay 0.72, floor 0.15×c | decay 0.55, floor 0.10×c + 5-epoch linger | decay **0.40**, floor **0.05×c** + 10-epoch linger | decay **0.30**, floor **0.02×c** + 24-epoch linger |
| **Sim reputation soft rotate** | — | — | `rep_signal_scale=0.45` | `rep_signal_scale=0.75` |
| **Sim aggressive tier** | — | extra 0.75× decay on dirty | aggressive + rep extra 0.88 | aggressive + rep extra 0.78 |
| **Rust sticky hard cap** | 12 epochs | 8 epochs | **4 epochs** | **2 epochs** |
| **Rust soft sticky** | disabled (soft=hard) | disabled (soft=hard) | soft from age **2** | soft from age **1** |
| **Rust peer spike** | threshold 2 | threshold 1 | threshold 1 | threshold 1 |

| Layer | Mechanism |
|-------|-----------|
| **Sim** | `mode='mitigated_v4'` (best long-horizon), `mitigated_v3`, `mitigated` (v2), `mitigated_first` (v1), `mitigated_aggressive` |
| **Rust** | [`GuardMitigationPolicy`](../../crates/aegis-topology/src/guard_mitigation.rs) — presets `adaptive_first()`, `adaptive_v2()`, `adaptive_v3()`, **`adaptive_v4()`** |
| **Trust** | [`peer_health_spike_detected`](../../crates/aegis-trust/src/policy.rs) — count threshold hook for topology |

Production defaults remain unchanged (`GuardMitigationPolicy::disabled()`).

### Why v3 (mid-horizon) then v4 (E=2000)

Parameter sweeps (`sim/scripts/sweep_adaptive_mitigation.py`) showed hard epoch-age
caps + decaying stickiness + reputation-aware soft rotate dominate mid-horizon
exposure vs v2. Wave **S5** locks **v4** for the E=2000 saturation residual:
tighter hard/soft sticky + stronger demotion. Maps onto client
`GuardMitigationPolicy` (hard cap, soft band, anomaly / peer-spike rotate).

### v3 / v4 results (honest)

At `c=0.015`, `g=3` (committed artifacts):

- Unmitigated adaptive: ~1.0 by E=200
- v1 (`mitigated_first`): ~0.90 at E=200
- v2 (`mitigated`): ~0.77 at E=200
- **v3 (`mitigated_v3`): ~0.45 at E=200**; ~0.99 at E=2000
- **v4 (`mitigated_v4`): ~0.24 at E=200**; ~0.85 at E=2000 (~14 pp better than v3)

Long horizons still saturate toward 1.0.
**§13 remains [O] QUANTIFIED + Partial mitigation.** See
`sim/data/adaptive_v4_saturation.analysis.json`.

## Enforcement point: **client**

Guard selection and path pinning happen on the **client** when building a bound
path (`GuardSelector` / `build_bound_path_pruned_with_guards_mitigated`). Relay
nodes parse `[guard_mitigation]` for operator symmetry but **do not** select
client paths.

### Client TOML (primary)

```toml
[guard_mitigation]
preset = "adaptive_v4"   # "adaptive_first" | "adaptive_v2" | "adaptive_v3" | "adaptive_v4"; omit = disabled

# Legacy (still supported when preset omitted):
# adaptive_first = true

[path]
epoch_age = 1            # pilot: epochs since last guard re-sample (v4 hard cap = 2)
anomaly_demotion_flag = false
peer_anomaly_count = 0
# Opt-in jurisdiction diversity (default off — safe). Soft path filter only;
# charter/legal quota enforcement remains External (see faction_sybil_skew.md).
# require_diverse_jurisdictions = true
# max_per_jurisdiction = 1
```

Parsed into [`GuardMitigationFileConfig`](../../crates/aegis-topology/src/guard_mitigation.rs)
and resolved to `GuardMitigationPolicy::adaptive_v4()` (hard sticky cap 2, soft
band from 1), `adaptive_v3()`, `adaptive_v2()`, or `adaptive_first()` (legacy).

At path build time, the client CLI and library callers use [`build_client_bound_path`](../../crates/aegis-client/src/path.rs)
(or topology's `build_bound_path_pruned_with_guards_mitigated` /
`build_bound_path_diverse_pruned_with_guards_mitigated` when diversity is on) with:

1. **`GuardMitigationSignals`** — `epoch_age`, `anomaly_demotion_flag`,
   `peer_anomaly_count` from `[path]` when set (defaults zero/false when telemetry unavailable).
2. **`apply_to_config_with_signals`** — sets `GuardPinMode::Rotate` under signal.
3. **`client_seed_for_guards`** — re-mixes client seed when `should_resample_guards`.
4. **Optional jurisdiction diversity** — when `[path] require_diverse_jurisdictions = true`,
   mitigation runs first, then diverse-pruned path selection
   (`max_per_jurisdiction`, default 1).

When signals are absent, `adaptive_v4` / `adaptive_v3` still apply soft-band /
hard-cap rotation and rotate-on-anomaly / peer-spike thresholds once wired.

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
- v4 lowers E=2000 exposure vs v3 but mitigated curves still approach 1.0 at long horizons — **[O]**.
- Roster paths require `[[hops]]` KEM registry entries (or live key fetch, not wired).
- Fused Mode-1 coupling under recompromise: see `fused_defense.py` (S5); does not close §13.

## Regenerate artifact + tests

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py --only adaptive
cd sim && PYTHONPATH=. python scripts/run_adaptive_v4_saturation.py
cd sim && PYTHONPATH=. python scripts/sweep_adaptive_mitigation.py          # CI + offline
cd sim && PYTHONPATH=. python scripts/sweep_adaptive_mitigation.py --ci-only
cd sim && PYTHONPATH=. pytest -q \
  tests/test_hardening.py::test_mitigated_v3_improves_mid_horizon_vs_v2 \
  tests/test_hardening.py::test_mitigated_v3_still_saturates_long_horizon \
  tests/test_hardening.py::test_mitigated_v4_improves_e2000_vs_v3 \
  tests/test_hardening.py::test_adaptive_mitigation_param_sweep_ci_bound \
  tests/test_fused_defense.py
```

Rust:

```bash
cargo test -p aegis-topology guard_mitigation
cargo test -p aegis-client guard_mitigation
cargo test -p aegis-client path::
cargo test -p aegis-client hops_resolve
cargo test -p aegis-node guard_mitigation
```
