# Cover multi-hop defenses (wave S4 / C5 extension)

**Status:** **[O] QUANTIFIED** — ranked in-sim; **not** info-theoretic indistinguishability.

Extends coverage C5 (`cover_multihop`) with policies that raise `implied_packet_continuity` toward Sphinx-only and/or lower `semantic_gap_score`.

## Threat (short)

Wire cover is τ-paced and AEAD-sealed, but `COVER_FRAGMENT_RESERVED` discards at the next hop — cover never peels/forwards. A GPA with ≥2 hop vantage sees wire≠forward yield even when single-hop gap CV looks cover-like.

## Schemes ranked

| Scheme | Idea | Product analogue |
|--------|------|------------------|
| `baseline_local_discard` | Today's local discard cover | `cover_flow.rs` reserved-byte discard |
| `matched_local_discard` | Identical cover schedule on every hop | Synchronized cover bursts (policy) |
| `cover_onions` | Cover packets that forward like Sphinx then sink | Future peelable cover onions |
| `cover_onions_plus_matched` | Onions + matched local discard | Combined policy |
| `sphinx_only_reference` | No cover (continuity upper bound) | Reference only |

## Recommendation

Prefer **`cover_onions`** (or **`cover_onions_plus_matched`**) in-sim — restores `implied_packet_continuity ≈ 1.0` by matching forward semantics. Product still needs real Sphinx-shaped cover construction; until then, **matched local discard** is the low-risk ops lever (lower hop volume L1) without claiming continuity recovery.

## Honest residuals

- Sim cover onions are not valid Sphinx ciphertext.
- Matched discard alone cannot restore continuity when cover never forwards.
- Single-hop gap CV may still look τ-like under all schemes.

## Evidence

| Piece | Path |
|-------|------|
| Sim | `sim/aegis_sim/cover_multihop_defense.py` |
| Artifact | `sim/data/cover_multihop_defense.analysis.json` |
| Tests | `sim/tests/test_cover_multihop_defense.py` |
| C5 baseline | `sim/data/cover_multihop_characterization.json` |
| Product note | `crates/aegis-relay/src/cover_flow.rs` (honest limitation + padding policy) |

```bash
cd sim && PYTHONPATH=. python scripts/run_cover_multihop_defense.py
cd sim && PYTHONPATH=. pytest -q tests/test_cover_multihop_defense.py
```
