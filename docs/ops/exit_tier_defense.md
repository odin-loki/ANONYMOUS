# Exit-tier defenses (wave S4 / C2 extension)

**Status:** **[O] QUANTIFIED** — ranked in-sim; **not WAN closed**.  
**Product (wave A2):** opt-in `[exit].presence_pad` matched-Q decoy/idle pad on exit hops — **default off**.

Extends coverage C2 (`exit_tier_intersection`) with defense transforms that reduce tip-sparse intersection and/or volume ranking on the exit↔clearnet residual.

## Threat (short)

GPA at the exit clearnet link sees unshaped per-client volumes. Tip-sparse ∩ on co-active windows collapses toward a singleton; cumulative volume ranks the true originator far above `1/N`. Mode-1 receiver hard-cap does **not** transfer here.

## Schemes ranked

| Scheme | Idea | Product analogue |
|--------|------|------------------|
| `baseline` | Unshaped residual (C2) | Today (pad off) |
| `volume_equalize` | Equalize volumes among co-active clients | Exit egress equalizer (sim-only) |
| `exit_window_pad_up` | Pad active clients up to Q | Soft egress pad |
| `exit_window_hard_cap` | Flat Q when active | Exit-relay egress hard shape |
| `presence_pad` | Activate idle clients at matched flat Q | **`[exit].presence_pad`** (A2) |
| `matched_decoy` | When target active, emit K matched companions | Matched cover companions (sim-only) |
| `pool_hard_cap` | Every client emits exactly Q every epoch | Always-on exit-pool egress pad (sim-only) |

**Composite risk:** `0.55·P(∩ singleton) + 0.45·P(volume rank #1)` at **decision horizon E=100** (mid-horizon where C2 tip-∩ still differentiates). Long-horizon residual is reported separately.

## Recommendation

Prefer **`presence_pad`** (matched-Q decoys) as the practical sim recommendation; **`pool_hard_cap`** is strongest but costliest. `matched_decoy` helps tip-∩ when real flows are active. `volume_equalize` / active-only hard-cap do not stop presence-frequency volume leaks.

## Product: `[exit].presence_pad` (wave A2)

Shipped in `aegis-node` exit sink. **Safe default: off.** Enable **only on designated exit hops** — mix relays must leave `[exit]` unset / pad disabled so unknown next-hops stay silent.

```toml
[exit]
deliver_to = "file:/var/lib/aegis/exit_payloads.log"   # or "stdout"
presence_pad = true          # opt-in; default false
pad_q = 10                   # matched-Q cells/epoch (sim DEFAULT_PAD_Q)
epoch_ms = 1000              # epoch length
presence_rate_pct = 55       # idle-epoch decoy chance (sim 0.55)
```

| Behavior | Detail |
|----------|--------|
| Active epoch | Pads **up** to `pad_q` with `decoy:presence_pad:active:…` lines on `deliver_to` |
| Idle epoch | With probability `presence_rate_pct`, emits `pad_q` idle decoys |
| Over-Q real | Real peels are **not** truncated (product cannot safely defer clearnet delivery) |
| Mix relays | Do not enable — `operator_check` warns when pad is on |

### Operator cost & residuals

- **Bandwidth / I/O cost:** idle inject at ~`presence_rate_pct%` × `pad_q` cells/epoch plus active pad-up; expect material egress growth vs unshaped exit.
- **Exit hops only:** never enable on intermediate mix relays.
- **Clearnet residual remains:** destinations cannot run Mode-1 `HardCapPadder`; a GPA on the exit↔server link still sees ordinary (now padded) clearnet volume. This is **not** a WAN C2 close.
- **Decoy markers:** file/stdout lines are operator-auditable (`decoy:presence_pad:…`). Production clearnet cover wiring (opaque TCP of matched size) is ops-side beyond this hook.
- **Pool hard-cap not shipped:** always-on full-pool flat-Q remains sim-only (highest cost).

## Honest residuals

- Synthetic Poisson model — not operational exit C2.
- Clearnet destinations cannot run `HardCapPadder`.
- Decoy schemes need honest peers or exit-injected cover; adversaries may refuse client-side participation (exit-injected pad does not require idle clients).
- Strong external tip knowledge can still shrink sets when pads miss tip windows.
- Long-horizon tip-∩ can re-collapse when pads are intermittent.

## Evidence

| Piece | Path |
|-------|------|
| Sim | `sim/aegis_sim/exit_tier_defense.py` |
| Artifact | `sim/data/exit_tier_defense.analysis.json` |
| Tests | `sim/tests/test_exit_tier_defense.py` |
| Product | `crates/aegis-node/src/exit_sink.rs`, `[exit]` in `config.rs` |
| C2 baseline | `sim/data/exit_tier_intersection.analysis.json` |

```bash
cd sim && PYTHONPATH=. python scripts/run_exit_tier_defense.py
cd sim && PYTHONPATH=. pytest -q tests/test_exit_tier_defense.py
cargo test -p aegis-node presence_pad -- --nocapture
```
