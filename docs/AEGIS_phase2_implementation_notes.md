# AEGIS Phase 2 — `aegis-crypto` Implementation Notes

This document records concrete design decisions for the Phase-2 Sphinx cryptographic
core. It does **not** modify `docs/AEGIS_SPEC_v3_consolidated.md` (frozen source of truth).

## Packet type and size

| Field | Size (bytes) | Offset |
|-------|-------------:|-------:|
| `alpha` (X25519 ephem + ML-KEM-768 ct) | 1120 | 0 |
| `beta` (routing onion, 6 fixed slots) | 7104 | 1120 |
| `gamma` (per-hop integrity MAC) | 32 | 8224 |
| `delta` (payload onion) | 256 | 8256 |
| **Total `SPHINX_PACKET_LEN`** | **8504** | |

- **`MAX_HOPS = 6`** — supports acceptance tests for path lengths 2..=6 with unused
  routing slots filled with CSPRNG randomness (length unchanged).
- The 512-byte [`Cell`](../../crates/aegis-crypto/src/cell.rs) remains the **link-layer**
  unit (ChaCha20-Poly1305 in `link.rs`). Sphinx packets are a separate, larger type.

### Routing slot layout (`ROUTING_SLOT_LEN = 1184`)

```text
next_hop_id (32) || next_kem_header (1120) || next_gamma (32)
```

Six slots are statically allocated in `beta`; only `path_len - 1` forward slots are used.

## Primitive choices (alpha / beta / gamma / delta)

| Field | Primitive | Rationale |
|-------|-----------|-----------|
| **alpha** | Hybrid X25519 + ML-KEM-768; `secret = SHA3-256(ss_x25519 ‖ ss_mlkem)` | Spec §4.1 PQ claim; implemented in `kem.rs`. |
| **beta** | SHA3-256 stream XOR per fixed routing slot; shift-left peel with deterministic tail pad (`SHA3("aegis-beta-peel-pad-v1" ‖ secret)`) | Constant 7104 B; unused slots random. |
| **gamma** | Keyed SHA3-256: `SHA3-256("aegis-gamma-mac-v1" ‖ secret ‖ beta)`; verified with `subtle` constant-time compare | Anti-tagging; next-hop MAC pre-embedded during build via peel simulation. |
| **delta** | SHA3-256 stream XOR layered with all hop secrets at build; one XOR peel per hop | LIONESS wide-block deferred — correctness risk vs. schedule; documented fallback. End-to-end integrity relies on `gamma` per hop. |

### Replay tag

`SHA3-256("aegis-replay-tag-v1" ‖ secret)` — domain-separated from MAC/stream keys.

### Link layer (`link.rs`)

ChaCha20-Poly1305 AEAD: `nonce (12) || ciphertext (512) || tag (16)` = 580 B frame,
AAD `b"aegis-link-v1"`.

## Phase-2 gate properties

| Property | How satisfied |
|----------|----------------|
| Constant size across path lengths | By construction: `SPHINX_PACKET_LEN` fixed; unused slots random-padded. |
| Tampered packet rejected | `gamma` MAC over full `beta`; test flips beta byte → `IntegrityFailure`. |
| Replay rejected | Per-hop `replay_tag` + `ReplayCache`; test processes twice → `Replay`. |
| Hybrid KEM KAT | Self-consistent encap/decap equality (deterministic relay keys + live encapsulation RNG); documented in `vectors.rs` — no official cross-implementation vector in repo. |
| Per-hop bitwise unlinkability | **Partial / best-effort**: independent per-hop hybrid KEM headers, fresh tail padding on peel; full Sphinx-style DH blinding (`blind_next`) implemented but peel copies next header from `beta` (documented in `kem.rs`). Formal proof remains spec §13 open item. |

## Deviations from illustrative spec figures

1. **512 B cell** — retained for link/dummy traffic only; Sphinx packets are 8504 B.
2. **LIONESS delta** — not implemented; stream-XOR onion chosen for correctness and test coverage.
3. **`sphinx::process` on `Cell`** — returns `Malformed`; callers must use `SphinxPacket`.

## Tests

- Gate: `crates/aegis-crypto/tests/vectors.rs` (gate + edge-case property/KAT tests, unignored).
- Additional unit tests: `kem.rs`, `sphinx.rs` (peel-pad invariants, multi-hop forward, tamper offsets), `link.rs` (tamper offsets, link AEAD).
- **Status (2026-07-18):** edge cases added (max hops, empty payload, hop-count boundaries, peel-pad invariants, seeded build KAT). Formal Sphinx proof remains spec §13 open item **[O]** — not claimed here.
