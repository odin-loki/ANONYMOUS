# AEGIS `aegis-crypto` — Security Profiling Review

This document records the Phase-2 security-profiling pass over `aegis-crypto`:
fuzz/property testing, constant-time review, dependency audit, and
nonce/domain-separation analysis. It supplements
`docs/AEGIS_phase2_implementation_notes.md` without modifying the frozen spec.

**Date:** 2026-07-12  
**Scope:** `crates/aegis-crypto` only (parsers: Sphinx, link AEAD, fragmentation, KEM decap).

---

## 1. Fuzz / property testing

### Approach

| Item | Detail |
|------|--------|
| **Fuzz targets created** | `fuzz/fuzz_targets/fuzz_sphinx_process.rs`, `fuzz_link_open.rs`, `fuzz_fragment_reassemble.rs`, `fuzz_kem_decap.rs` |
| **Toolchain** | `cargo-fuzz` 0.13.2, `rustup` nightly 1.99.0, `llvm-tools-preview` |
| **Build result** | All four targets **compile** with `cargo +nightly fuzz build <target>` |
| **Run result (Windows)** | **Could not execute** — runtime exits `0xC0000135` (`STATUS_DLL_NOT_FOUND`) for the MSVC AddressSanitizer / libFuzzer runtime DLL. Rebuilding with `--sanitizer none` fails at link time (`__start___sancov_cntrs` unresolved on `x86_64-pc-windows-msvc`). This is known Windows + cargo-fuzz friction. |
| **Fallback executed** | `tests/parser_fuzz_properties.rs` — four `proptest` harnesses mirroring the libFuzzer attack surface |

### Property-test configuration and results

```
ProptestConfig { cases: 10_000 } per target
Total malformed-input trials: 40_000 (4 × 10_000)
Wall time: ~233 s (debug profile, Windows)
```

| Target | Attack surface | Result |
|--------|----------------|--------|
| `fuzz_sphinx_process_never_panics` | Arbitrary 8504 B `SphinxPacket` → `process()` with fixed relay secret + bounded replay cache | **Clean** — no panics, no OOB reads |
| `fuzz_link_open_never_panics` | Arbitrary bytes as 580 B frame (and short/overlong slices) → `LinkKey::open` | **Clean** |
| `fuzz_fragment_reassemble_never_panics` | Arbitrary `Cell` sequences → `SphinxReassembler::push` / `reassemble` | **Clean** |
| `fuzz_kem_decap_never_panics` | Arbitrary bytes as KEM header → `RelayKemSecret::decapsulate` | **Clean** |

**Crashes found and fixed:** none (clean bill of health after 40 000 property iterations).

**Recommendation:** Run `cargo +nightly fuzz run <target> -- -max_total_time=60` on Linux/macOS CI where libFuzzer + sanitizers are fully supported. Keep the `proptest` tests as a Windows-compatible regression gate.

### Build hygiene note

A clean rebuild exposed a latent **module/crate name shadowing** bug: the local module `kem` shadowed the external `kem` trait crate. Fixed by renaming the dependency to `kem-api` in `Cargo.toml` and `use kem_api::{Decapsulate, Encapsulate}` in `src/kem.rs`. No public API change.

---

## 2. Constant-time review

Manual grep for `==` / `!=` on secret-derived data and review of control flow
in `kem.rs`, `sphinx.rs`, `link.rs`.

### `kem.rs`

| Checked | Lines | Finding |
|---------|------:|---------|
| Secret byte comparisons (`SharedSecret`, KEM outputs) | 119–126, 154–158 | **None.** No `==` on shared secrets or ML-KEM/X25519 outputs. |
| Branching on decap result | 122–125 | Branches on `try_from` / `decapsulate` **errors** (malformed ct), not on secret byte values — acceptable. |
| Loop bounds / table lookups | 161–164 (`blinding_scalar`) | Fixed-length SHA3 digest → scalar; no secret-dependent iteration count. |

**Verdict:** No constant-time defects found. No fixes required.

### `sphinx.rs`

| Checked | Lines | Finding |
|---------|------:|---------|
| Gamma MAC verification | 179–183 (`verify_mac`) | **Correct:** `expected.ct_eq(actual).into()` via `subtle::ConstantTimeEq`. |
| `process` control flow | 194–196 | Early return on `!verify_mac(...)` **after** constant-time compare. The branch itself may leak pass/fail via timing (standard limitation); not a byte-comparison leak. |
| Replay tag | 171–176, 198–200 | Tag derived then passed to `ReplayCache` (out of scope — see note below). |
| Stream XOR loops | 299–322, 254–273 | Counter-driven fixed bounds (`end - start`, `len`); domain + secret feed SHA3 only — no secret-dependent loop termination. |
| `PartialEq` on `SphinxPacket` | 64 | Derives equality on full packet bytes — **test/debug only**, not used on secrets in the hot path. |

**Verdict:** MAC comparison is constant-time. No fixes required.

### `link.rs`

| Checked | Lines | Finding |
|---------|------:|---------|
| AEAD tag verification | 56–64 | Delegated to `chacha20poly1305::ChaCha20Poly1305::decrypt`, which performs constant-time Poly1305 tag check internally. |
| `==` on lengths | 50–51, 65–66 | Compares `frame.len()` and `pt.len()` to public constants — **non-secret**. |
| Nonce handling | 55, 35–37 | Nonce taken from wire; no comparison of nonce bytes to secrets. |

**Verdict:** No constant-time defects found. No fixes required.

### Out-of-scope note (`replay.rs`) — **addressed (2026-07-17)**

~~`ReplayCache::check_and_insert` uses `HashSet::contains(&tag)` (line 65) — **not** constant-time.~~

**Update:** membership now uses a fixed-length scan over the FIFO window with
`subtle::ConstantTimeEq` (see `replay.rs` module docs). `HashSet` is retained
for insert/eviction/generation-drop bookkeeping only. **Residual:** O(capacity)
CPU per check; final branch on aggregated `Choice`; no `dudect` proof yet.

### Statistical timing smoke test

`tests/timing_smoke.rs` — 2 000 trials each of `verify_mac` on valid vs last-byte-flipped packet; asserts median latency ratio &lt; 3×.

**Result:** Passed (coarse smoke only; **not** a rigorous side-channel proof).

**Future work:** `dudect` / `ctgrind` on Linux with CPU isolation and pinned frequency.

---

## 3. Dependency audit

### `cargo audit` (2026-07-12)

```
$ cargo audit
    Loaded 1160 security advisories
    Scanning Cargo.lock for vulnerabilities (165 crate dependencies)
```

**Result: CLEAN** — no advisories reported for workspace dependencies.

### `cargo deny`

Not run. Setting up `deny.toml` (licenses, bans, sources) is a workspace-level policy task beyond this crate pass. `cargo audit` alone is the recorded minimum.

---

## 4. Nonce reuse and domain separation

### Link-layer AEAD (`link.rs`)

| Property | Analysis |
|----------|----------|
| Nonce generation | `LinkKey::seal` fills 12 bytes from CSPRNG (`rng.fill_bytes`) per call — **unique random nonce per seal**. |
| Birthday bound | ChaCha20-Poly1305 nonce is 96 bits. Expected collisions: \(n^2 / 2^{97}\). Even at \(10^9\) frames per key lifetime, collision probability ≪ \(10^{-9}\). **Practically safe** for any realistic link session. |
| Nonce reuse risk | Only if caller reuses RNG output or replays an old frame verbatim under the same key (protocol-layer concern). Implementation does not reuse nonces. |
| AAD | Fixed `b"aegis-link-v1"` on every seal/open — consistent. |

### Sphinx symmetric primitives (`sphinx.rs`)

These use **counter-mode SHA3-256 stream XOR**, not AEAD nonces:

| Constant | Purpose | Collision risk |
|----------|---------|------------------|
| `aegis-gamma-mac-v1` | Keyed SHA3 MAC over `beta` | Domain-separated from streams/replay/pad |
| `aegis-beta-stream-v1` | Per-slot routing onion XOR | Distinct prefix |
| `aegis-delta-stream-v1` | Payload onion XOR | Distinct prefix |
| `aegis-replay-tag-v1` | Replay tag derivation | Distinct prefix |
| `aegis-beta-peel-pad-v1` | Deterministic tail pad on peel | Distinct prefix |

All prefixes are unique ASCII strings with version suffix `-v1`. No two cryptographic purposes share the same domain string. Counter `to_le_bytes()` in stream functions prevents keystream reuse within a single `(domain, secret)` pair.

**Verdict:** Domain separation is consistent. No nonce-reuse issues in the AEAD sense; stream counters are adequate for fixed field widths (`ROUTING_SLOT_LEN`, `DELTA_LEN`).

---

## 5. Files added / modified

### New files

- `crates/aegis-crypto/fuzz/Cargo.toml`
- `crates/aegis-crypto/fuzz/fuzz_targets/fuzz_sphinx_process.rs`
- `crates/aegis-crypto/fuzz/fuzz_targets/fuzz_link_open.rs`
- `crates/aegis-crypto/fuzz/fuzz_targets/fuzz_fragment_reassemble.rs`
- `crates/aegis-crypto/fuzz/fuzz_targets/fuzz_kem_decap.rs`
- `crates/aegis-crypto/tests/parser_fuzz_properties.rs`
- `crates/aegis-crypto/tests/timing_smoke.rs`
- `docs/AEGIS_crypto_constant_time_review.md` (this file)

### Modified (build hygiene only; no public API/behavior change)

- `crates/aegis-crypto/Cargo.toml` — `proptest` dev-dep; `kem` crate renamed `kem-api` to avoid module shadowing
- `crates/aegis-crypto/src/kem.rs` — `use kem_api::{Decapsulate, Encapsulate}`

---

## 6. Verification

```
$ cargo test -p aegis-crypto
29 passed (19 unit + 4 property + 1 timing smoke + 5 integration/vectors)
0 failed
```

Phase-2 gate vectors (`tests/vectors.rs`) remain green after all changes.

---

## 7. Future work

1. Linux CI job: `cargo +nightly fuzz run` × 4 targets, 60 s each, with corpus check-in.
2. `dudect` / `ctgrind` MAC-verification and AEAD-open timing proofs.
3. ~~Constant-time replay-cache membership (or HMAC-blinded lookup).~~ **Done (2026-07-17):** fixed-capacity CT scan in `ReplayCache::ct_contains`. Residual: O(capacity) cost; `dudect` proof.
4. Workspace `cargo deny` policy (`deny.toml`).
5. Optional: seed libFuzzer corpora from passing `proptest` inputs for cross-platform fuzz continuity.
