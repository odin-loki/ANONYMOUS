# Exit-tier defenses (wave S4 / C2 extension)

**Status:** **[O] QUANTIFIED** — ranked in-sim; **not WAN closed**.

Extends coverage C2 (`exit_tier_intersection`) with defense transforms that reduce tip-sparse intersection and/or volume ranking on the exit↔clearnet residual.

## Threat (short)

GPA at the exit clearnet link sees unshaped per-client volumes. Tip-sparse ∩ on co-active windows collapses toward a singleton; cumulative volume ranks the true originator far above `1/N`. Mode-1 receiver hard-cap does **not** transfer here.

## Schemes ranked

| Scheme | Idea | Product analogue |
|--------|------|------------------|
| `baseline` | Unshaped residual (C2) | Today |
| `volume_equalize` | Equalize volumes among co-active clients | Exit egress equalizer (sim-only) |
| `exit_window_pad_up` | Pad active clients up to Q | Soft egress pad |
| `exit_window_hard_cap` | Flat Q when active | Exit-relay egress hard shape |
| `presence_pad` | Activate idle clients at matched flat Q | Decoy / cover clearnet flows |
| `matched_decoy` | When target active, emit K matched companions | Matched cover companions |
| `pool_hard_cap` | Every client emits exactly Q every epoch | Always-on exit-pool egress pad |

**Composite risk:** `0.55·P(∩ singleton) + 0.45·P(volume rank #1)` at **decision horizon E=100** (mid-horizon where C2 tip-∩ still differentiates). Long-horizon residual is reported separately.

## Recommendation

Prefer **`presence_pad`** (matched-Q decoys) as the practical sim recommendation; **`pool_hard_cap`** is strongest but costliest. `matched_decoy` helps tip-∩ when real flows are active. `volume_equalize` / active-only hard-cap do not stop presence-frequency volume leaks.

## Honest residuals

- Synthetic Poisson model — not operational exit C2.
- Clearnet destinations cannot run `HardCapPadder`.
- Decoy schemes need honest peers or exit-injected cover; adversaries may refuse.
- Strong external tip knowledge can still shrink sets when pads miss tip windows.

## Evidence

| Piece | Path |
|-------|------|
| Sim | `sim/aegis_sim/exit_tier_defense.py` |
| Artifact | `sim/data/exit_tier_defense.analysis.json` |
| Tests | `sim/tests/test_exit_tier_defense.py` |
| C2 baseline | `sim/data/exit_tier_intersection.analysis.json` |

```bash
cd sim && PYTHONPATH=. python scripts/run_exit_tier_defense.py
cd sim && PYTHONPATH=. pytest -q tests/test_exit_tier_defense.py
```
