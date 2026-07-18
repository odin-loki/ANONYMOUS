# Crypto / Phase-2 threat-model gap ledger (Wave S2)

**Date:** 2026-07-18  
**Tip baseline:** 3819c1b  
**Scope:** Open/Partial rows for `aegis-crypto` plus crypto-adjacent link, fragment, replay, and client send-path crypto.  
**Out of scope:** Sphinx Python oracle (S1), Tamarin (S3), anonymity sims, hardware TEE.  
**Primary evidence:** `crates/aegis-crypto/tests/threat_model_gaps.rs`  
**Threat model:** `docs/AEGIS_implementation_threat_model.md` §1 (+ client send rows)

| ID | Finding (short) | Prior status | Disposition | Evidence | Residual sev |
|----|-----------------|--------------|-------------|----------|--------------|
| TM-CRYPTO-01 | Opaque `PathHop::id` — no PKI in crypto crate | Open | **Accepted assumption** | `opaque_hop_ids_roundtrip_on_peel`; roster bind in topology/client | Low |
| TM-CRYPTO-02 | Link AEAD anonymous; handshake identity binding | Partial | **Partial / Tested** | `link_binding_rejects_wrong_peer_id`, `link_binding_rejects_wrong_kem_commitment`, `link_aead_frame_has_fixed_width_without_peer_id_field` | Low (PSK held in config; frames stay anonymous) |
| TM-CRYPTO-03 | MAC verify branch after `ct_eq` may leak timing | Partial | **Accepted residual** | `tampered_gamma_always_integrity_failure` (functional); timing → S6/`dudect` | Low |
| TM-CRYPTO-04 | Fixed 8512 B × 18 fragments — no crate rate limit | Partial | **Accepted assumption** | `fixed_packet_and_fragment_surface`, `sphinx_packet_len_matches_layout_constants`; rate limit in `aegis-relay` ingress | Low |
| TM-CRYPTO-05 | Replay cache flood / O(capacity) CT scan | Mitigated (residual) | **Mitigated / Tested**; residual accepted | `replay_rejects_duplicates_in_window`, `replay_len_bounded_under_flood` | Low |
| TM-LINK-01 | Hop link auth (LegacyPsk + Auto/Noise) | Partial/Mitigated | **Partial / Tested** (binding); Noise path ops-doc | Same as TM-CRYPTO-02 + `docs/ops/noise_link_auth.md` | Low–medium (shared ingress PSK/static) |
| TM-CLIENT-01 | Client may pick arbitrary hop ids | Mitigated / open if malicious | **Accepted assumption** | `aegis-client/tests/kem_binding.rs`; crypto trusts ids (TM-CRYPTO-01) | Low |
| TM-CLIENT-02 | Raw `send_payload` / `--raw` unpaced cadence | Soft-closed | **Accepted residual** | Deprecated API + `PacedSession` default; fragment invariants in gap tests | Low–medium (High if misusing raw) |

## Summary counts

| Disposition | Count |
|-------------|------:|
| Closed by property test (mitigation quantified) | 3 (TM-CRYPTO-02 binding, TM-CRYPTO-05, size invariants in TM-CRYPTO-04) |
| Accepted assumption (by design / out-of-crate) | 3 (TM-CRYPTO-01, TM-CRYPTO-04 rate limit, TM-CLIENT-01) |
| Accepted residual (honest leftover) | 3 (TM-CRYPTO-03 timing, TM-LINK-01 PSK/Noise, TM-CLIENT-02 raw) |

All prior Open/Partial rows in §1 `aegis-crypto` are either **Tested**, **Accepted assumption**, or **Accepted residual** — none remain bare Open.

## Verify

```text
cd crates && cargo test -p aegis-crypto --test threat_model_gaps
```

## Doc bug fix (S2)

Stale **8504** B Sphinx size corrected to **8512** in `aegis-crypto/src/sphinx.rs` module docs and threat-model DoS row (matches `SPHINX_PACKET_LEN` / `fragment.rs`).
