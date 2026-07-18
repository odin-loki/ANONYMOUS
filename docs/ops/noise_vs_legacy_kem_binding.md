# Noise_IK vs LegacyPsk + KEM binding (research note)

**Date:** 2026-07-18  
**Tip baseline:** 3819c1b  
**Wave:** S6 (CT / SoftHSM / Noise)  
**Scope:** Code-backed comparison of hop-link auth modes. Not a formal proof; no Tamarin.

**Code anchors:**

| Path | Role |
|------|------|
| `crates/aegis-crypto/src/noise_link.rs` | `Noise_IK_25519_ChaChaPoly_BLAKE2s` via `snow` |
| `crates/aegis-crypto/src/link.rs` | LegacyPsk MAC + `LinkHandshakeBinding` (relay id ± KEM commitment) |
| `crates/aegis-relay/src/net.rs` | Mode selection, ingress fail-closed, handshake runners |
| `crates/aegis-node/src/config.rs` | TOML: `handshake`, `require_ingress_kem_commitment`, `kem_commitment` |
| `docs/ops/noise_link_auth.md` | Operator Noise configuration |

## Summary

| Property | Noise_IK | LegacyPsk + KEM binding |
|----------|----------|-------------------------|
| Mutual auth material | Per-node static X25519 (roster publics) | Shared PSK + optional roster relay id / KEM commitment in MAC |
| Forward secrecy (handshake) | Ephemeral DH in Noise IK | Ephemeral X25519 + PSK-MAC session derive |
| Identity binding | Encrypted static in msg1; responder CT-checks expected initiator pk | `LinkHandshakeBinding.peer_relay_id` in confirm/finish MAC |
| Roster KEM commitment in handshake | **No** | **Yes** when `with_kem_commitment` / peer `kem_commitment` set |
| Ingress KEM require flag | **Fail-closed** if Noise selected | Enforced on MAC path; unset local commitment also fail-closed |
| Wire sizes | msg1 96 B / msg2 48 B | Init / resp / confirm / finish MAC frames (legacy sizes) |
| Session key | SHA3-256(`aegis-noise-session-v1` ‖ Noise hs hash) → `LinkKey` | SHA3-256 mix of DH shared + transcript → `LinkKey` |
| Cell AEAD after HS | Unchanged 580-byte ChaCha20-Poly1305 cells | Same |

**Operator rule of thumb:** Use Noise_IK when hop mutual auth via static keys is the goal. Keep **LegacyPsk** (or Auto without Noise keys) when `require_ingress_kem_commitment = true` — Noise cannot satisfy that binding today.

## Property detail

### Noise_IK (`handshake = "noise"` or Auto + statics)

- Pattern: `Noise_IK_25519_ChaChaPoly_BLAKE2s` (`snow`).
- Initiator must know responder static public; responder decrypts initiator static from msg1 and accepts only if it matches peer-table / ingress expectation (`into_session_if_peer_matches` / CT eq).
- Wrong responder static → AEAD / `IntegrityFailure` on msg1 processing.
- Wrong initiator static → session rejected after decrypt (`IntegrityFailure`).
- Does **not** feed `kem_public_commitment` into the Noise transcript or AEGIS session domain mix.
- Residual: AEGIS `LinkKey` is a domain-separated hash of the Noise handshake hash (not raw Noise transport keys); ingress still admits any holder of the configured ingress static (or derived ingress key).

### LegacyPsk + KEM binding (`handshake = "legacy_psk"` or Auto without Noise keys)

- Ephemeral X25519 + PSK-derived auth key; confirm/finish MACs over transcript.
- Optional `LinkHandshakeBinding`:
  - Always (when `identity_binding`): responder relay id domain-separated into MAC.
  - Optional: 32-byte roster KEM public-key commitment (`0x01 ‖ commitment` vs `0x00` absent).
- Stolen PSK for peer A cannot authenticate as peer B without matching identity (and KEM) binding material.
- Matching KEM on both sides succeeds; mismatch → MAC verify fail / unidentified inbound.
- Relay-id-only still allowed when commitment absent (unless require flag forces commitment).

## Fail-closed cases (from code)

| Condition | Behavior |
|-----------|----------|
| `require_ingress_kem_commitment` and `local_kem_commitment` unset | Responder returns Malformed **before** handshake bytes (covers Noise and LegacyPsk) |
| `require_ingress_kem_commitment` and responder selects Noise | Malformed: `"require_ingress_kem_commitment needs LegacyPsk handshake (Noise does not bind KEM commitment)"` |
| Config load: require flag without top-level `kem_commitment` | Config error (`aegis-node`) |
| Noise without local static secret (`handshake = "noise"`) | Config error |
| Noise wrong static / decrypt fail | `IntegrityFailure` / no session |
| LegacyPsk KEM mismatch | Confirm/finish MAC fail → no session / `UnidentifiedInbound` |
| Auto mix: one side Noise (has secret), other LegacyPsk (no keys) | Handshake fails (modes disagree) |
| Explicit `legacy_psk` | Never selects Noise |

Regression coverage (in-tree):

- `aegis-crypto` `link.rs`: matching / mismatched / absent KEM commitment unit tests.
- `aegis-relay` `net.rs`: `matching_kem_commitment_handshake_succeeds`, mismatch fails, require-without-local fails, require-with-match succeeds, initiator-without-binding rejected, **`require_ingress_kem_commitment_rejects_noise_path`**.
- `aegis-crypto` `noise_link.rs`: honest roundtrip, wrong responder static, wrong initiator static.

## Security comparison table (code reading)

| Threat / goal | Noise_IK | LegacyPsk + KEM |
|---------------|----------|-----------------|
| Impersonate hop without peer static / PSK | Hard (need static or break Noise) | Hard (need PSK); binding stops cross-peer reuse |
| Bind hop to roster KEM pubkey commitment | **Not provided** | **Provided** (MAC binding) |
| Silent loss of KEM binding under “secure” Noise Auto | **Blocked** (fail-closed if require flag + Noise) | N/A (MAC path) |
| PSK compromise → forge as any peer | N/A (statics) | Mitigated if identity (± KEM) binding on |
| Static key compromise → forge as that node | Yes (Noise threat model) | N/A |
| PQ / KEM hybrid into hop HS | Out of scope on Noise path today | Commitment bind only (not a PQ handshake) |
| Formal Noise security proof for AEGIS `LinkKey` mix | Not claimed | Not claimed |

## Residuals (honest)

1. **No KEM in Noise transcript** — operators who need ingress KEM commitment must stay on LegacyPsk (or disable the require flag and accept the gap).
2. **KEM binding ≠ KEM handshake** — LegacyPsk binds a commitment hash into a classical PSK-MAC; it is not a post-quantum key exchange.
3. **Auto migration** — deployments without `noise_static_*` remain LegacyPsk; partial key rollout can cause asymmetric mode selection and failed links.
4. **Session key domain mix** — both paths end in AEGIS `LinkKey` + existing cell AEAD; cell frames are not Noise transport.
5. **Ingress trust** — shared ingress key / ingress Noise static still admits any authorized ingress holder; roster peer-table auth is stricter.
6. **This note** — research / ops guidance only; not EasyCrypt / Tamarin.

## Optional sim pointer

In-tree executable checks already encode the comparison (prefer those over a new defense sim):

```bash
cd crates
cargo test -p aegis-crypto noise_ik_ -- --nocapture
cargo test -p aegis-crypto handshake_ -- --nocapture
cargo test -p aegis-relay require_ingress_kem -- --nocapture
```

## Related

- Operator Noise: [`noise_link_auth.md`](noise_link_auth.md)
- Wave tracker: [`PC_VERIFY_RESEARCH_WAVE.md`](PC_VERIFY_RESEARCH_WAVE.md) § S6
- SoftHSM ceremony (orthogonal custody track): [`softhsm_ceremony.md`](softhsm_ceremony.md)
- CT evidence: [`constant_time_ci.md`](constant_time_ci.md)
