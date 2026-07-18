# Cover multi-hop defenses (wave S4 / C5 extension → product A3 / B1)

**Status:** **[O] QUANTIFIED** in-sim; **partial product** — matched local discard + peelable `cover_onions` (terminal → sink) shipped (opt-in). Scaffold remains available. **Not** info-theoretic indistinguishability.

Extends coverage C5 (`cover_multihop`) with policies that raise `implied_packet_continuity` toward Sphinx-only and/or lower `semantic_gap_score`.

## Threat (short)

Wire cover is τ-paced and AEAD-sealed, but `COVER_FRAGMENT_RESERVED` discards at the next hop — cover never peels/forwards. A GPA with ≥2 hop vantage sees wire≠forward yield even when single-hop gap CV looks cover-like.

## Schemes ranked

| Scheme | Idea | Product analogue |
|--------|------|------------------|
| `baseline_local_discard` | Today's local discard cover | Default `[cover]` pad-to-target |
| `matched_local_discard` | Identical cover schedule on every hop | **Shipped (opt-in):** fixed `matched_cover_flows` per round |
| `cover_onions` | Cover packets that forward like Sphinx then sink | **Shipped (opt-in, B1):** valid Sphinx to terminal peer → peel-then-discard at `COVER_SINK_HOP_ID` |
| `cover_onions_scaffold` | Tagged reserved marker only | **Shipped:** still local-discard (no peel) |
| `cover_onions_plus_matched` | Onions + matched local discard | Sim-only combined policy |
| `sphinx_only_reference` | No cover (continuity upper bound) | Reference only |

## Recommendation

Prefer **`cover_onions`** (or **`cover_onions_plus_matched`**) in-sim — restores `implied_packet_continuity ≈ 1.0` by matching forward semantics.

**Product:**
- Prefer **`matched_local_discard`** when peer KEM publics are unavailable — low-risk volume alignment.
- Prefer **`cover_onions`** when a terminal peer KEM public is configured (lab: `[[peers]]` `kem_*` seeds) — emits **valid Sphinx** fragments that the terminal peels, then sinks at `COVER_SINK_HOP_ID` (not client exit traffic).
- `cover_onions_scaffold` remains the discard-only tagged path.

## Opt-in TOML

```toml
[cover]
enabled = true
require = true

# Peelable cover onions (distinct from scaffold):
multihop_defense = "cover_onions"
cover_onion_flows = 1
cover_onion_peer_id = "0200…00"   # optional; else first peer with kem seeds

# Or matched discard volume alignment:
# multihop_defense = "matched_local_discard"
# matched_cover_flows = 2

# Or scaffold only — still discarded before peel:
# multihop_defense = "cover_onions_scaffold"
```

```toml
[[peers]]
id = "0200…00"
addr = "127.0.0.1:9101"
link_key = "…"
# Lab/pilot: derive peer KEM public for cover-onion build (not production PK distribution).
kem_x25519_seed = "…"
kem_mlkem_d = "…"
kem_mlkem_z = "…"
```

Peers on a path should share the same `multihop_defense` (+ matched/onion counts) so cover schedules align.

## What peelable cover onions are / are not

**Are:**
- Valid Sphinx ciphertext (reserved-zero fragments; enter reassembly).
- Peeled at the configured terminal hop.
- Explicitly sunk at `COVER_SINK_HOP_ID` (payload discarded; not forwarded; not exit-delivered).

**Are not:**
- Real client application traffic or exit delivery.
- Full multi-hop forwardable cover paths (only terminal → sink today; intermediate forward hops deferred).
- Info-theoretic indistinguishability from client Sphinx.

## Honest residuals

- Without a terminal KEM public, `cover_onions` emits **no** peelable flows (mode stays distinct from scaffold).
- Peer KEM seeds in TOML are a **lab** public-derivation path; production needs roster/directory PK distribution.
- Matched discard alone cannot restore `implied_packet_continuity` when cover never forwards.
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
