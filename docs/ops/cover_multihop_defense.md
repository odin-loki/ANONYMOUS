# Cover multi-hop defenses (wave S4 / C5 extension → product A3)

**Status:** **[O] QUANTIFIED** in-sim; **partial product** — matched local discard shipped (opt-in); cover onions scaffold only. **Not** info-theoretic indistinguishability.

Extends coverage C5 (`cover_multihop`) with policies that raise `implied_packet_continuity` toward Sphinx-only and/or lower `semantic_gap_score`.

## Threat (short)

Wire cover is τ-paced and AEAD-sealed, but `COVER_FRAGMENT_RESERVED` discards at the next hop — cover never peels/forwards. A GPA with ≥2 hop vantage sees wire≠forward yield even when single-hop gap CV looks cover-like.

## Schemes ranked

| Scheme | Idea | Product analogue |
|--------|------|------------------|
| `baseline_local_discard` | Today's local discard cover | Default `[cover]` pad-to-target |
| `matched_local_discard` | Identical cover schedule on every hop | **Shipped (opt-in):** fixed `matched_cover_flows` per round |
| `cover_onions` | Cover packets that forward like Sphinx then sink | **Scaffold only:** `COVER_ONION_SCAFFOLD_RESERVED` (still discarded) |
| `cover_onions_plus_matched` | Onions + matched local discard | Sim-only combined policy |
| `sphinx_only_reference` | No cover (continuity upper bound) | Reference only |

## Recommendation

Prefer **`cover_onions`** (or **`cover_onions_plus_matched`**) in-sim — restores `implied_packet_continuity ≈ 1.0` by matching forward semantics.

**Product (wave A3):** prefer **`matched_local_discard`** first — low-risk ops lever that aligns discard/volume across peer hops sharing the same TOML. `cover_onions_scaffold` reserves a distinct wire marker for a future peel/forward-then-sink construction; it does **not** restore Sphinx continuity today.

## Opt-in TOML

```toml
[cover]
enabled = true
require = true
# Align cover discard volume across peer hops (independent of local real count).
multihop_defense = "matched_local_discard"
matched_cover_flows = 2

# Scaffold only — still discarded before peel; no continuity claim:
# multihop_defense = "cover_onions_scaffold"
# cover_onion_flows = 1
```

Peers on a path should share the same `multihop_defense` + `matched_cover_flows` so discard cell counts match.

## Honest residuals

- Sim cover onions are not valid Sphinx ciphertext; product scaffold is still local discard (`COVER_ONION_SCAFFOLD_RESERVED`).
- Matched discard alone cannot restore `implied_packet_continuity` when cover never forwards — residual vs Sphinx forward remains.
- Single-hop gap CV may still look τ-like under all schemes.
- Not info-theoretic indistinguishability.

## Evidence

| Piece | Path |
|-------|------|
| Sim | `sim/aegis_sim/cover_multihop_defense.py` |
| Artifact | `sim/data/cover_multihop_defense.analysis.json` |
| Sim tests | `sim/tests/test_cover_multihop_defense.py` |
| Product | `crates/aegis-relay/src/cover_flow.rs` (`CoverMultihopDefense`) |
| Node TOML | `crates/aegis-node` `[cover] multihop_defense` |
| C5 baseline | `sim/data/cover_multihop_characterization.json` |

```bash
cd sim && PYTHONPATH=. python scripts/run_cover_multihop_defense.py
cd sim && PYTHONPATH=. pytest -q tests/test_cover_multihop_defense.py
cargo test -p aegis-relay cover_ --lib
cargo test -p aegis-node cover_ --lib
```
