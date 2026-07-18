# Combined active(n−1) + intersection → Mode-1 hard-cap (sim → product)

**Status:** **[O] QUANTIFIED** — characterized in-repo; **not closed**.

This maps the fused-attack simulator to the production hard-cap path operators must enable.

## Threat (short)

Global passive intersection over long horizons, composed with active sender suppression (n−1 confirmation), on Mode-1 constant-rate traffic. Evidence and ranking: `sim/aegis_sim/combined_active_intersection.py`, artifact `sim/data/combined_active_intersection.analysis.json`.

## Sim schemes → product

| Sim scheme | Observable | Product analogue | Fused-attack result (sim) |
|------------|------------|------------------|---------------------------|
| `constant_only` | raw counts | Mode-1 sender without receiver hard-cap | Saturates → ~1.0 by long E |
| `pad_up` | max(real, Q) | “Pad up to Q” heuristic | Above baseline; high Q helps but ≠ hard-cap |
| `truncate_only` | min(real, Q) | Cap without dummy fill | Leaks (under- and over-Q) |
| `noisy_hard_cap` | Q + 0.4·(real−Q) | Partial transparency / fill tracks load | Saturates like constant_only |
| `hard_cap` | exactly Q | Ideal Mode-1 receiver pad | ~baseline 1/M |
| `deferred_hard_cap` | exactly Q (FIFO defer) | **`HardCapPadder`** | Ties `hard_cap` (attack-visible) |

**Recommended defense:** `hard_cap` / `deferred_hard_cap` (same attack-visible invariant). No evaluated scheme **beats** hard-cap under this adversary without lying about what production can observe.

## Rust product path

| Piece | Location |
|-------|----------|
| Padder | `crates/aegis-client/src/padding.rs` — `HardCapPadder`, `CountHardCapPadder` |
| Config | `HardCapConfig { q }` — observable deliveries per round |
| Invariant | Every `round_tick()` returns exactly `q` slots (real + `Dummy`) |
| Deferral | Excess real arrivals stay in FIFO backlog (latency, not shape) |
| Demo / gate | `crates/aegis-client/tests/hardcap_demo.rs`; unit tests in `padding.rs` |
| Sim twin | `sim/aegis_sim/shaper.py::hard_cap` + `deferred_hard_cap` scheme |

**Q rule (sim + product):** `Q ≥ ~1.2 ×` sustained mean arrivals per round. At `ρ = mean/Q → 1`, deferral tails blow; security of the *shape* still holds if the observable stays flat, but the service is not stably provisioned.

## What operators must enable

1. **Mode-1 paced sessions** — do not run production on `--raw` / deprecated unpaced send APIs.
2. **Receiver-side hard-cap padding** — `HardCapPadder` (or equivalent) with `Q` meeting the 1.2× rule.
3. **Internal tier** — both endpoints run AEGIS. Hard-cap is a *receiver* participation requirement.

Do **not** disable hard-cap for “efficiency” in favor of pad-up or truncate: those remain vulnerable to the fused attack in sim.

## Exit-tier exclusion (residual)

Clearnet exit / non-AEGIS receivers **cannot** apply `HardCapPadder`. Spec §8 / Phase 8 exit-tier notes: receiver-side fused-attack resistance **does not transfer** to that tier. Sender-side constant-rate emission may still hold up to the exit relay; the exit↔clearnet link is ordinary encrypted traffic to a GPA there.

This residual is why the research agenda still lists the item as **not mitigated** in the production-science sense even when internal-tier hard-cap holds in sim.

## Regenerating evidence

```bash
cd sim && PYTHONPATH=. python scripts/generate_research_artifacts.py --only combined
cd sim && PYTHONPATH=. pytest -q tests/test_combined_active_intersection.py tests/test_hardening.py -k combined
```

Offline long-horizon curves (E≥3200) live under `offline_long_horizon` in the artifact; CI tests use short grids only.

## Honest limits

Synthetic Poisson traffic; shared global timeline; no multi-hop mix delay, guard rotation, or Sphinx proofs. Numbers characterize the model — they do **not** close spec §13.
