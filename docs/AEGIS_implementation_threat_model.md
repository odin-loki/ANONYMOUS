# AEGIS — Implementation-Level Threat Model

**Date:** 2026-07-12 (mitigation sync **2026-07-17**)  
**Scope:** Maps the paper threat model in `docs/AEGIS_SPEC_v3_consolidated.md` §2–§9 onto the **actual Rust/Python code** in this workspace.  
**Adversary baseline:** Nation-state global passive adversary (GPA) + active fraction `f` of compromised mixes, for a **permissioned consortium** mixnet.  
**Cross-references:** `docs/AEGIS_crypto_constant_time_review.md` (crypto side channels), `docs/AEGIS_phase8_hardening_notes.md` (real-trace / adaptive-adversary quantification). This document does **not** repeat those findings.

**Rating scale:** informational / low / medium / high — relative to the spec's intended deployment (consortium, vetted relays, internal client↔client traffic).

---

## Executive summary — highest-severity open gaps

| # | Finding | Crate / location | Severity |
|---|---------|------------------|----------|
| 1 | **`send_payload` / legacy paced send go quiet after 18 ticks** — unpaced burst and one-shot paced path expose true cadence at client TCP ingress. **Soft-closed (2026-07-17):** default CLI uses `PacedSession` with continuous dummy cover + connection reuse; `send_payload` / `send_payload_with_options` are `#[deprecated]` (traces/`--raw` only). Residual: deliberate raw integration or `--raw` still unpaced. | `aegis-client::send`, `aegis-client::session`, CLI `--raw` | **Low–medium** (was Medium; High if misusing raw API) |
| 2 | **~~No admission rate limit~~** — ~~compromised consortium signing key ⇒ unlimited signed Sybil relays; fresh Sybils get NEUTRAL reputation (0.5) and pass the 0.3 floor immediately.~~ **Mitigated (2026-07-12):** probationary admission reputation (0.1) + configurable rate limit (default 5/24h). **Mitigated (2026-07-17):** M-of-N threshold admission (`ThresholdConsortium` / `admit_threshold_signed`). Live peer-health drains feed EWMA via `feed_peer_outcomes` (`aegis-node` 30s). Residual: consortium key ceremony out of band. | `aegis-topology::roster`, `aegis-trust::reputation` | **Low–medium** (was High) |
| 3 | **Hop link auth (LegacyPsk + optional Noise)** — default: per-TCP X25519 ECDH + PSK MAC with **`LinkBridgeConfig::identity_binding`**. **Partial/Mitigated (2026-07-17):** optional `LinkHandshakeMode::Noise` (`noise-link`) runs a Noise_IK-compatible mutual auth with roster static X25519 keys (`PeerConfig.noise_static_public`); see `docs/ops/noise_link_auth.md`. Residual: default still LegacyPsk; Noise transcript uses SHA3 not BLAKE2s (not full Noise/`snow`); ingress admits holders of the configured ingress static/PSK; static secrets still operator-distributed. | `aegis-crypto::link`, `aegis-crypto::noise_link`, `aegis-relay::net`, `aegis-node::config` | **Low–medium** (was Medium) |
| 4 | **Relay error/load counters observable** — fine-grained per-error counters remain available via [`RelayHandle::debug_stats`] for in-process tests only; external surfaces must use [`RelayHandle::coarse_stats`] (aggregated buckets). Residual GPA risk if coarse buckets are scraped at high frequency under flood. | `aegis-relay::node::RelayCoarseStats` | **Low–medium** (was Medium) |
| 5 | **Replay cache eviction under sustained flood** — **Mitigated (2026-07-17):** CT FIFO membership scan (`ct_contains`); generation/`advance_epoch()` + proactive shorten at 85% fill on large caches. Residual: O(capacity) CPU per check; shortened window under flood is intentional trade-off. | `aegis-crypto::replay` | **Low** (was Medium) |

---

## Methodology

For each crate: read `src/lib.rs` and skim modules; STRIDE pass with **module/function citations**, mitigation status (with code reference), and severity. "No issue" entries document *why* the code matches the spec assumption.

Simulations backing numeric claims:
- Sybil: `crates/aegis-topology/tests/sybil_admission.rs`
- Malicious trace: `crates/aegis-node/tests/trace_capture.rs::capture_malicious_burst_trace_to_csv`, `sim/scripts/analyze_malicious_trace.py`

---

## 1. `aegis-crypto`

**Role:** Sphinx packet build/peel, hybrid KEM, link AEAD, fragmentation, replay cache (spec §4.1).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Hop identity in Sphinx routing slots is 32-byte opaque id; no PKI binding to roster admission in this crate. | `sphinx::build`, `PathHop::id` | **Open gap** — roster binding is in `aegis-topology`; crypto layer trusts caller-supplied ids. | Low (by design; admission is out-of-crate) |
| Link frames carry no peer identity inside AEAD — session auth from ephemeral ECDH + PSK MAC; roster `RelayId` bound in confirm/finish MAC when `identity_binding` enabled. | `link::LinkKey::open`, `link::link_handshake_*`, `LinkHandshakeBinding` | **Partial (2026-07-17)** — per-connection forward secrecy; stolen peer-A PSK cannot auth as peer B when binding on. Residual: config-held PSK; AEAD frames still anonymous. | — |

### Tampering

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Gamma MAC verified with constant-time compare before peel. | `sphinx::verify_mac`, `sphinx::process` | **Mitigated** — see constant-time review. | — |
| AEAD tag check delegated to ChaCha20-Poly1305. | `link::LinkKey::open` | **Mitigated**. | — |
| Tampered Sphinx packet yields `IntegrityFailure` (whole payload randomized on failed MAC). | `sphinx::process` | **Mitigated** — Phase-2 gate property. | — |

### Repudiation

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No sender signatures on payloads; unlinkability is the goal. | `sphinx::build` | **N/A** — repudiation not a property. | informational |

### Information disclosure

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Per-hop peel reveals only next-hop id to relay (standard Sphinx). | `sphinx::process` → `Processed::Forward` | **Mitigated** by onion design. | — |
| MAC verify pass/fail may leak via timing (branch after `ct_eq`). | `sphinx::process` | **Partial** — documented in constant-time review; not byte-comparison leak. | Low |
| `ReplayCache::check_and_insert` membership scan. | `replay.rs` (`ct_contains`) | **Mitigated (2026-07-17)** — fixed-capacity CT equality scan over FIFO window; `HashSet` not used on check path. Residual: O(capacity) CPU; branch after aggregated compare. | Low |
| Fixed packet size regardless of path length. | `SphinxPacket`, `SPHINX_PACKET_LEN` | **Mitigated**. | — |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Bounded replay cache with generation advance under flood. | `replay::ReplayCache::with_capacity`, `advance_epoch` | **Mitigated (2026-07-17)** — proactive generation advance at 85% fill; CT membership scan; epoch rollover remains primary defense. Residual: O(capacity) per-check cost. | **Low** (was Low–medium) |
| `process()` on arbitrary bytes returns errors without panic (proptest/fuzz gate). | `sphinx::process`, `tests/parser_fuzz_properties.rs` | **Mitigated**. | — |
| Large fixed packets (8504 B Sphinx + 18 fragments) — CPU/memory per flood packet. | `fragment`, `sphinx` | **Partial** — no explicit rate limit in crate. | Low |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No privilege model in crate; relay secret only peels one layer. | `sphinx::process` | **Mitigated** — cannot skip layers without keys. | — |

**Overall:** Crypto core matches Phase-2 gate properties. Residual issues are replay-cache O(capacity) CPU cost and link-layer auth (delegated to deployment). **Do not re-audit constant-time details here** — see `AEGIS_crypto_constant_time_review.md`.

---

## 2. `aegis-relay`

**Role:** Mix relay — Sphinx peel, Exp(μ) delay, forward, bulk cover-flow (spec §4.4, §5.2–§5.3).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Ingress accepts TCP peers with correct ingress PSK; handshake MAC binds to responder relay id when `LinkBridgeConfig::identity_binding` is true (default). | `net::run_responder_handshake`, `link::LinkHandshakeBinding` | **Partial (2026-07-17)** — roster id binding blocks cross-peer PSK replay; any holder of the shared ingress key + correct first-hop id still admitted. Residual: no client roster proof at link layer. | **Low–medium** (was Medium) |
| Forward routing uses `next_hop` from peeled Sphinx only. | `node::process_one_packet` | **Mitigated** — cannot forward to arbitrary id without valid onion. | — |

### Tampering

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Integrity/replay errors increment counters, packet dropped. | `node::process_one_packet` L288–299 | **Mitigated** — no forward on failure. | — |

### Repudiation

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No audit log of forward decisions. | — | **N/A** for mixnet threat model. | informational |

### Information disclosure

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Per-hop mixing delay sampled from Exp(μ) — timing visible to GPA on link. | `delay::sample_mixing_delay` | **By design** — delay is not the security primitive (spec §4.4); cover provides metadata hiding. | informational |
| Cover flows are emitted as [`Command::SphinxFragment`] cells on hop links (AEAD-sealed, same frame width as real bulk). Reserved-byte marker `COVER_FRAGMENT_RESERVED` prevents inbound reassembly/peel; cover never enters the Sphinx forward path. **Update (2026-07-17):** cover dispatcher paces cells at Mode-1 τ (`LinkBridgeConfig::cover_cell_tau`, default 0.35s) so inter-cell gaps match client paced bulk. Residual: multi-hop Sphinx semantics still differ (cover discarded next hop; invalid onion). | `cover_flow.rs`, `node.rs` cover channel, `net.rs` cover dispatcher | **Partial (2026-07-17)** — volume/count + τ-aligned inter-cell timing; multi-hop/shape GPA residual remains. |
| `RelayCoarseStats` exposes only aggregated `processed_ok` / `processed_fail` / `cover_emitted` for external export. Fine-grained per-error counters live in [`RelayHandle::debug_stats`] (documented internal-only). | `node::RelayCoarseStats`, `node::RelayDebugStats` | **Mitigated** for external metrics — do not export `debug_stats`. Residual if coarse buckets scraped under flood. | Low–medium |
| `ForwardedPacket::delay_applied` records delay (internal struct). | `node::ForwardedPacket` | Low risk unless logged. | Low |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Inbound/outbound `mpsc` channels (capacity 64). | `node::RELAY_CHANNEL_CAPACITY`, `aegis-node` `main`, `net::run_inbound_connection` | **Mitigated (2026-07-17)** — bounded channels; on full, **drop-newest** via `try_send_drop_newest` (never block forever under flood). Coarse counters: `RelayCoarseStats::queue_dropped` (outbound), `QueueDropStats` (inbound). **Per-peer fair inbound (2026-07-17):** each TCP connection has a `PER_PEER_INBOUND_CAPACITY` queue; round-robin drain into the shared mix inbound so one peer cannot monopolize. Residual: equal-weight RR (not weighted WFQ); outbound still shared. | **Low** |
| Malicious/raw clients flood ingress cells unbounded into the mix queue. | `net::run_inbound_connection`, `IngressRateLimitConfig` | **Mitigated (2026-07-17)** — per-connection token bucket (default ≈1/τ cells/s, burst 4) **plus default-on global shared budget** (`DEFAULT_GLOBAL_MAX_CELLS_PER_SEC` = 8/τ ≈ 22.86 cells/s; TOML `[link]` / `[ingress]`). Excess frames **dropped silently**; coarse `IngressRateLimitStats::dropped_frames` only. Residual: limits apply after TCP accept/handshake; connection stays open; mis-set caps can drop honest paced clients; `max_inbound` still admits handshake load. | **Low** (was Medium) |
| Mixing delay serializes packets per relay task — flood increases queue latency. | `node::process_one_packet` L268–269 | **Mitigated** for availability; **leaks** load via timing (see above). | Medium |
| Single relay task — no worker pool. | `node::spawn` | **Partial** — CPU saturation under flood. | Low |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Compromised relay sees plaintext at its hop (standard mixnet). | `sphinx::process` | **Assumed** in spec §2 (`f` fraction). | — |
| Bulk round commands via `RelayHandle` — no auth on handle (in-process only). | `node::RelayHandle::begin_bulk_round` | **N/A** in production API surface today. | informational |

---

## 3. `aegis-topology`

**Role:** Stratified topology, guards, path selection, permissioned roster, beacon (spec §4.5–§4.7, §4.9).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| `RelayId::from_u64` is placeholder — not PK-derived from KEM keys. | `types::RelayId` | **Mitigated (2026-07-17)** — production ids via `RelayId::from_kem_commitment` (`SHA3-256(aegis-relay-id-v1 \|\| commitment)`); signed admit rejects mismatch when `RosterAdmissionPolicy::require_kem_derived_id` (default true). `from_u64` retained for non-admission fixtures only. | Low (fixture misuse) |
| Signed admission binds id + jurisdiction + KEM commitment via ed25519. | `roster::admit_threshold_signed`, `RelayRecord::binds_kem_public` | **Mitigated** when production path used; path builders must call `binds_kem_public` before encapsulation. | — |
| Test-only `RelayRoster::admit()` skips signature. | `roster::admit` / `admit_for_tests` | **Mitigated (2026-07-17)** — unsigned admit compiled only under `cfg(test)` or feature `test-utils` (default off); `admit` marked `#[deprecated]`; production must use signed APIs. Residual: enabling `test-utils` in a prod binary re-opens the gap. | Low (was High if misused) |

### Tampering

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Tampered signed record rejected on verify. | `roster::tests::tampered_record_fails_verification` | **Mitigated**. | — |
| ~~Roster JSON load without authority key skips re-verify.~~ | `roster::load_from_file_with_policy` | **Mitigated (2026-07-17)** — production path requires consortium keys and re-verifies; unverified load only via explicit `allow_unverified_roster` / `load_from_file_unverified` (lab/test). Keys present always force verify. Residual: callers must wire the policy API (node/client `[roster]` does). | Low |

### Repudiation

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| ~~Single consortium signing key~~ — M-of-N threshold admission via [`ThresholdConsortium`](../../crates/aegis-topology/src/roster.rs). | `roster::ThresholdConsortium`, `admit_threshold_signed` | **Mitigated (2026-07-17)** — `ThresholdSignedRelayRecord::verify_threshold` requires M distinct authority signatures; `admit_signed` remains 1-of-1 convenience. Residual: authority key ceremony / PKI out of band. | Low |

### Information disclosure

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Stable guard fixed for epoch — GPA learns entry guard identity for that client epoch. | `guards::GuardSelector::primary_guard` / sticky pin | **By design** — exposure bounded by plateau math if `c` small; backups held in g-set. | informational |
| ~~**Implementation uses only `primary_guard()` (g=1 effective)**~~ — held set is `GUARD_SET_SIZE=3`; path builders pin via `entry_guard_for_packet` (sticky primary default; `GuardPinMode::Rotate` for plateau-style cycling). Production: `build_bound_path_pruned_with_guards` + reputation-weighted g-set. | `guards::GuardSelector::{guard_set,primary_and_backups,entry_guard_for_packet}`, `path::select_path_indexed` | **Mitigated (2026-07-17)** — g=3 set + production multi-guard helpers. Residual: sticky primary still g=1 *entry pin* (GPA learns one identity); unfiltered `select_path` / `GuardSelector::new` remain for research. | Low (was Medium) |
| Path inner hops fresh CSPRNG per packet. | `path::select_path` L64–84 | **Mitigated**. | — |
| `HashChainBeacon` predictable from seed — dev only. | `beacon.rs` | **Mitigated** in prod path via `ThresholdBeacon`; dev mode documented. | Low |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| `select_diverse_path` / reputation paths exhaust after `max_attempts`. | `path.rs:98–109, 127–148` | **Partial** — returns error; caller must handle. | Low |
| ~~Unbounded signed admission rate~~ — capped by [`RosterAdmissionPolicy`](../../crates/aegis-topology/src/roster.rs) (default 5/24h). | `roster::admit_signed`, `admit_threshold_signed` | **Mitigated** — returns `AdmissionRateLimitExceeded`. Sybil sim: attacker capped to 5 Sybils/window vs 500 pre-fix. | — |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Compromised consortium key ⇒ arbitrary signed admissions. | `roster::ThresholdConsortium`, `admit_threshold_signed` | **Mitigated** — rate limit slows flood; M-of-N requires compromising ≥M distinct authorities. Residual: small M or correlated authority compromise. | **Low–medium** (was High) |
| Reputation floor 0.3 does not block new Sybils (default NEUTRAL 0.5). | `aegis-trust::reputation` + `guards::new_reputation_weighted` | **Mitigated** — `admit_new_relay` seeds `PROBATIONARY` (0.1) at signed admission; Sybil sim rep-filtered path capture 0.0% vs ~45% pre-fix at 50% flood. | — |
| Sybil flood raises unfiltered sticky-primary capture ≈ layer-1 Sybil fraction; held g=3 set tracks `1-(1-c)^g`. **Admission + reputation** (rate limit 5/24h, probation 0.1, M-of-N, `new_reputation_weighted` / `build_bound_path_pruned_with_guards`) block **fresh** Sybils so g=3+rep set capture ≈0 under flood. Residual: unfiltered APIs still saturate under majority layer-1 flood (honest science — see `sybil_majority_flood_unfiltered_g1_saturates`). | `guards::guard_exposure_plateau`, `GUARD_SET_SIZE`, `tests/sybil_admission.rs` | **Partial / Mitigated (2026-07-17)** — production multi-guard + rep filter closes paper gap for vetted/probationary Sybils; residual is unfiltered path/guard APIs + honest-pool failure at extreme c. | **Medium** (was High) |

**Sybil simulation summary:** See §Simulation results below.

---

## 4. `aegis-trust`

**Role:** EWMA reputation, ZK range proofs, anomaly detector, TEE bookkeeping (spec §4.8, Phase 7).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| `PlaintextReputationProof` embeds score — not ZK. | `zk::PlaintextReputationProof` | **Mitigated** by docs — production must use `BulletproofsReputationProof`. | Low if misconfigured |
| ZK proofs do not hide relay identity (module docs). | `zk.rs` / `AnonymousReputationPresentation` | **Partial (2026-07-17)** — `present_anonymous` / `verify_anonymous` ship Bulletproofs threshold proofs with **no RelayId in proof bytes**; identity binding via out-of-band `derive_reputation_nullifier` + `score_commitment`. Residual: no full AC / consensus issuer / wire gossip — see `docs/ops/anonymous_reputation.md`. | Low–medium |

### Tampering

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Bulletproofs verify threshold on scaled integer. | `zk::BulletproofsReputationProof::verify` | **Mitigated** for score threshold integrity. | — |
| In-memory ledger — no persistence or consensus. | `reputation::ReputationLedger` | **Partial (2026-07-17)** — optional JSON `save_to_file` / `load_from_file`; `aegis-node` `[reputation] ledger_path` loads on startup and saves on 30s peer-health drain + graceful shutdown. Residual: no cross-operator consensus; each node holds its own view. | Low–medium |

### Repudiation

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No signed reputation updates. | `reputation::record_success/failure` | **Partial (2026-07-17)** — in-memory EWMA updates remain unsigned (local process). Optional Ed25519 operator attestation at the persistence boundary: `save_to_file_signed` / `load_from_file_verified` over canonical `(decay, scores)`; `aegis-node` `[reputation]` `operator_signing_seed` / `operator_signing_key_file` / `operator_verifying_key`. Unsigned path unchanged when keys absent. Residual: no per-update wire signatures; no cross-operator consensus of reports. | Low |

### Information disclosure

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Plaintext ledger reveals all scores to holder. | `reputation::score` | **By design** until ZK + consensus wired. | informational |
| `below_threshold` lists bad relays. | `reputation::below_threshold` | **Mitigated** for operator use; not wire exposed. | — |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Unbounded `HashMap` of scores. | `reputation::ReputationLedger` | **Low** — one entry per relay id. | Low |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Unseen relay gets NEUTRAL 0.5 — immediately eligible for reputation-filtered paths/guards at min 0.3. | `reputation::score` L53–55 | **Partial** — relays with **no** ledger entry still default to NEUTRAL (backward compat / test-only `admit()`). Signed admissions seed `PROBATIONARY` (0.1) via `admit_new_relay`. | **Low–medium** (was High) |
| `AnomalyDetector` → path/guard selection and **new admission** via [`RelayPruningPolicy`](../../crates/aegis-trust/src/policy.rs) `*_pruned` APIs (`admit_signed_pruned` / `admit_threshold_signed_pruned`); [`PeerHealthTracker`](../../crates/aegis-relay/src/peer_health.rs) feeds failure rates and aggregate EWMA updates via [`feed_peer_outcomes`](../../crates/aegis-trust/src/policy.rs) (`aegis-node` drains every 30s); inbound responder handshakes record per-peer outcomes once a roster PSK matches. | `anomaly.rs`, `aegis-topology::{path,guards,roster}`, `aegis-relay::{peer_health,net,health_gossip}` | **Partial (2026-07-17):** admission gating Done via `admit_*_pruned` + live peer-health → ledger; signed [`PeerHealthAdvert`](../../crates/aegis-relay/src/health_gossip.rs) gossip over link-control cells (`Command::PeerHealthAdvert`) from peer-table neighbors (half-weight merge). See [`docs/ops/health_gossip.md`](ops/health_gossip.md). Residual: no global/BFT consensus; malicious admitted neighbors can still bias; unidentified inbound not attributed; callers must use pruned APIs. | **Low–medium** (was Medium) |
| TEE attestation vacuous / no hardware quote path. | `tee::{AttestationProvider, SoftwareAttestationProvider, core_gates_hold_under_attested}` | **Partial (2026-07-17)** — real trait + software Ed25519 provider for lab; `core_gates_hold_under(BrokenEnclave)` fails closed; attested gate passes with verified quote. Residual: no SGX/SEV SDK; software provider does not prove enclave integrity. See `docs/ops/tee_attestation.md`. | Low–medium |

---

## 5. `aegis-negotiator`

**Role:** Bulk security dial, F_max ceiling, cover requirement math, scheduler (spec §5).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Negotiator is protocol-not-server — no network surface in this crate. | all modules | **N/A**. | — |

### Tampering

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| `enforce_ceiling` rejects plans over F_max. | `ceiling::enforce_ceiling` | **Mitigated** for size policy. | — |

### Repudiation

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No persistent negotiation state. | — | **N/A** at library level. | — |

### Information disclosure

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| L0 dial explicitly exposes relationship (documented). | `dial::SecurityDial`, `dial_hides_relationship` | **By design** — dial choice is endpoint policy. | informational |
| Rendezvous id derivation — hamming distance helper only. | `rendezvous.rs` | Low metadata if ids leak. | Low |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Fragmentation of oversized bulk — policy in `ceiling`. | `ceiling::fragment_sizes` | **Mitigated** — forces pay mixnet cost or accept exposure. | — |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Cover requirement is advisory — relay must call `begin_bulk_round`. | `cover.rs` vs `aegis-relay` / `aegis-node` | **Mitigated (2026-07-17)** — `[cover]` defaults `enabled=true`/`require=true`; `RelayNode::spawn` fail-closed without cover channel when required; `start_bulk_cover` begins L2 rounds at node startup (+ optional rotation). Residual: in-process callers that leave `BulkCoverConfig` at defaults (enabled=false) and never call `start_bulk_cover` can still skip cover; round rotation interval is ops-tuned. | Low (was Medium) |

---

## 6. `aegis-client`

**Role:** Constant-rate emitter, hard-cap padding, Sphinx send helper (spec §4.2–§4.3).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Client chooses path hops explicitly in `send_payload`. | `send::ClientHop`, `send_payload` | **Mitigated** if path from topology; **open** if client maliciously picks paths. | Low |

### Tampering

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Payload integrity inside Sphinx delta. | `send::build_packet` → `sphinx::build` | **Mitigated**. | — |

### Repudiation

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No application-level signatures. | — | **N/A**. | — |

### Information disclosure

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| **`send_payload` / CLI `--raw` bypass emitter** — unpaced burst at client TCP ingress; GPA sees true cadence. | `send.rs`, CLI `--raw`, `trace_capture.rs` | **Soft-closed (2026-07-17)** — default CLI / [`PacedSession`](../../crates/aegis-client/src/session.rs) use continuous emitter + post-send cover; raw APIs `#[deprecated]` with allow only at intentional `--raw`/trace sites. Residual: one-time TCP/handshake per session; adversarial clients can still call raw. | **Low–medium** (High if misusing raw API) |
| Hard-cap padder emits exactly Q slots per round externally. | `padding::HardCapPadder::round` | **Mitigated** when used. | — |
| Dummy cells use CSPRNG padding. | `emitter::encode_dummy_cell` | **Mitigated**. | — |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Emitter queue unbounded on `enqueue`. | `emitter::ConstantRateEmitter` | **Partial** — memory DoS if client never ticks. | Low |
| ρ > 0.7 warning via `rho_at_peak_rate` only — not enforced. | `emitter::rho_at_peak_rate`, `PacedSession` / CLI paced path | **Mitigated (2026-07-17)** — `EmitterConfig::validate_rho` rejects λ_peak·τ > 0.7 when creating `PacedSession` / paced CLI (defaults τ=0.35, peak=2.0 → ρ=0.7); lab override via `--allow-high-rho` or `AEGIS_ALLOW_HIGH_RHO`. Residual: raw/`ConstantRateEmitter` direct construction still unconstrained. | — |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Malicious/custom client can bypass paced APIs and flood ingress. | deprecated `send_payload` vs [`PacedSession`](../../crates/aegis-client/src/session.rs) / CLI default; relay `IngressRateLimitConfig` | **Mitigated (2026-07-17)** — product default paced path + deprecated raw API; **relays now rate-limit ingress** (token bucket ≈1/τ cells/s, silent drop). Residual: adversarial client can still open many connections up to `max_inbound_connections`; handshake cost before rate limit; lab tests may disable the limiter. | **Low** (was Low–medium) |

---

## 7. `aegis-node`

**Role:** Runnable relay process — TOML config, KEM persistence, TCP bridge (spec §10 Phase 3).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Peer table from config file — wrong peer addr ⇒ misroute. | `config::NodeConfigFile`, `main.rs` | **Mitigated** by ops; no runtime discovery. | Low |
| KEM seeds written to disk on first run. | `config::load_or_init_kem` | **Partial / Mitigated (2026-07-17)** — default first-run writes seeds to a separate file (`kem.seeds` or `[kem] file`); main TOML holds path only. **Windows** (`kem-dpapi`, default): DPAPI user-scope (`CryptProtectData`) with magic `AEGIS-KEM-DPAPI-v1`. **Unix** (`kem-keyring`, default): OS keychain via `keyring` (service `aegis-node`, account = relay id or config-path hash) with pointer magic `AEGIS-KEM-KEYRING-v1`; falls back to plaintext + mode `0600` if the keychain is unavailable. Legacy plaintext seed files still load. Inline persistence requires `[kem] allow_plaintext_kem = true` (lab/test). Residual: DPAPI/keychain are same-user/session backends (not HSM); Unix residual when secret-service/keychain absent is still `0600` plaintext. | **Low** |

### Tampering

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Config file tampering changes peers/keys. | `config.rs` | **Mitigated** only by file permissions. | Medium |

### Repudiation

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No structured audit log. | `main.rs` | **N/A**. | — |

### Information disclosure

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| `eprintln!` startup logs relay id byte and listen addr. | `main.rs:41–44` | Low — operational leakage. | Low |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| mpsc(64) channels — same as relay. | `main.rs` (`RELAY_CHANNEL_CAPACITY`) | **Mitigated (2026-07-17)** — same drop-newest policy as `aegis-relay` (`try_send_drop_newest` + coarse counters). Residual: shared-channel fairness only. | **Low** (was Medium) |
| Multi-process testnet had peer routing failures (Phase 8 notes). | `sim/scripts/capture_multiprocess_trace.py` | **Partial (2026-07-17)** — last-hop `[exit]` file sink enabled in mp capture configs; prior “routing” errors were terminal peels without exit. Residual: full paced multi-process re-capture. | Low |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| `--mu` CLI override without auth. | `main.rs:36–37` | Local operator only. | Low |

---

## Simulation-backed findings

### A. Sybil admission (`sybil_admission.rs`)

**Methodology:** 24 honest + N attacker-signed Sybils via real `admit_signed` (with shared `ReputationLedger`); `build_topology` + `GuardSelector` + `select_path*`; 2000 client seeds; compare to `guard_exposure_plateau(c, g=3)`. Honest relays seeded with 30 EWMA successes above the 0.3 floor; Sybils start at `PROBATIONARY` (0.1) via `admit_new_relay`.

| Scenario | Layer-1 Sybil fraction | Sticky primary (g=1 pin) | Held g=3 set any-Sybil | Rep-filtered path / rep g=3 set | Paper ~3% plateau |
|----------|------------------------|--------------------------|------------------------|----------------------------------|-------------------|
| 0 Sybils (baseline) | 0% | ~0% | ~0% | ~0% / ~0% | — |
| 1 Sybil / 100 relays (c≈1%) | ~1% | **~1.0%** | **~1-(1-c)³ ≈ 3c** | **~0%** / **~0%** | ~2.97% |
| 24 + 24 Sybils (50% flood) | ~67% | **~67%** (unfiltered) | **~1-(1-c)³ ≈ saturates** | **~0%** / **~0%** (was ~45% path pre-fix) | >> 3% |
| 24 + 96 Sybils (80% flood) | ~67% | **~66%** unfiltered g=1 saturates | saturates unfiltered | **~0%** / **~0%** with rep | >> 3% |
| Rate-limited: 24 honest + 5 Sybils/window | ~0% | **~0%** | **~0%** | **~0%** | — |

**Fix (2026-07-12):** `ReputationScore::PROBATIONARY` (0.1) seeded at signed admission; `RosterAdmissionPolicy` default **5 admissions / 24h** (`AdmissionRateLimitExceeded`). Reputation-filtered path/guard selection now excludes fresh Sybils. **Fix (2026-07-17):** M-of-N threshold admission (`ThresholdConsortium`, default production path `admit_threshold_signed`); signed roster records include SHA3-256 hybrid KEM public-key commitments verified via `RelayRecord::binds_kem_public`; live relay peer-health drains update the shared EWMA ledger via `feed_peer_outcomes` / `record_aggregate` (optional JSON persistence via `[reputation] ledger_path`). **Fix (2026-07-17, workstream #9):** `GUARD_SET_SIZE=3`; `GuardSelector::{guard_set, primary_and_backups, entry_guard_for_packet}`; sticky primary (default) or rotate pin; production `build_bound_path_pruned_with_guards` builds reputation-weighted multi-guard + pruned path. **Residual risk:** consortium ceremony has ops tooling (`docs/ops/consortium_key_ceremony.md`, `aegis-ceremony`) but no HSM/Shamir MPC; probation / g=3 plateau improvement only when callers use reputation-aware multi-guard helpers; **unfiltered** `select_path` / sticky `primary_guard` still tracks layer-1 Sybil fraction under majority flood (documented by `sybil_majority_flood_unfiltered_g1_saturates`).

**Conclusion:** Held **g=3** set exposure tracks `guard_exposure_plateau(c, 3)`. Production defaults combine multi-guard + reputation filtering so fresh Sybils do not enter the g-set or pruned paths. Sticky primary remains a g=1 *entry pin* (GPA learns one identity per epoch) by design; rotate mode is available for plateau-style cycling. Unfiltered APIs remain for honest residual measurement and must not be used in production.

### B. Malicious flood trace (`capture_malicious_burst_trace_to_csv`)

**Methodology:** 80 packets, 2 ms inter-send gap, raw `send_payload` (no emitter) — **trace-only path**, not default CLI [`PacedSession`](../../crates/aegis-client/src/session.rs); compare `shapeability_report` to benign `real_testnet_trace.csv`. See `sim/data/real_testnet_malicious_trace.analysis.json` after capture.

**Measured results** (`real_testnet_malicious_trace.csv`, 80 sends, 2 ms requested gap):

| Metric | Malicious flood | Benign trace | Synthetic stand-in |
|--------|-----------------|--------------|-------------------|
| Duration | **7.1 s** | 71.9 s | — |
| Events/slot max | **12** | 4 | — |
| Events/slot mean | **10.0** | 0.67 | — |
| CV | **0.34** (tier: cheap) | 1.39 (feasible) | 1.25 |
| min_multiple | 1.1 | 1.1 | 2.6 |
| Client send_ok | **100%** | 100% | — |
| Ingress forwarded | 80/80 | 48/48 | — |

**Behavior:** Raw `send_payload` (and CLI `--raw`) bypass `ConstantRateEmitter` and bulk negotiator/cover-flow — the flood is **not shaped**. Default paced CLI would emit τ-shaped cells + dummy cover instead. **Update (2026-07-17):** production relays apply per-connection ingress token-bucket rate limiting (`IngressRateLimitConfig`, default ≈1/τ cells/s + small burst; excess frames dropped silently with a coarse drop counter). The historical CSV above was captured with the limiter disabled in `trace_capture` (lab flood path). With production defaults, an unpaced flood no longer unbounded-queues the mix; client `send_ok` may still succeed at TCP write while the relay drops excess frames. **Side-channel (raw path only):** sustained high `events_per_slot_max` (12 vs 4) remains observable to a GPA at client egress; relay processing latency under load vs idle is a residual if metrics or timing are visible (see `RelayCoarseStats`; post-shaping traces in Future work §8).

---

## Cross-crate trust boundaries

```
ConsortiumKey(s) ──M-of-N sign──► RelayRoster (+ KEM commitment) ──filters──► Topology ──feeds──► GuardSelector / select_path
                              ▲                           │
                              │                           └── ReputationLedger (optional floor)
Client ──default──► PacedSession / ConstantRateEmitter ──► Transport ──► mix
         trace/raw ──► send_payload / CLI --raw ─────────────► ingress (OBSERVABLE if misused)
Relay ──peel──► sphinx::process ──delay──► forward (GPA sees timing)
```

---

## Mitigations already aligned with spec

- Hybrid PQ KEM + Sphinx integrity/replay handling (`aegis-crypto`)
- Stable guards + plateau formula (`guards::guard_exposure_plateau`)
- Hard-cap padding semantics (`aegis-client::padding`)
- Default client egress via [`PacedSession`](../../crates/aegis-client/src/session.rs) / CLI (τ-shaped emission + post-send cover); `--raw` for trace capture only
- Permissioned admission **when** `admit_threshold_signed` (or 1-of-1 `admit_signed`) used with configured consortium authorities
- Roster↔KEM binding via signed `kem_public_commitment` (`RelayRecord::binds_kem_public`)
- TEE-not-required path documented (`aegis-trust::tee`)
- Honest bulk cover limitations documented (`aegis-relay::cover_flow`); cover bursts wired on hop links via cover outbound channel (`aegis-relay::net`); production `aegis-node` auto-starts bulk cover via `start_bulk_cover` with fail-closed `[cover].require`
- Unsigned `RelayRoster::admit` gated behind `cfg(test)` / feature `test-utils` (default off)

---

## Future work (implementation)

1. Wire **mandatory** `ConstantRateEmitter` on all client egress via [`PacedSession`](../../crates/aegis-client/src/session.rs) (continuous dummy cover + one TCP link per session); keep raw `send_payload` / `--raw` for adversarial trace capture only. **Done (2026-07-17):** CLI default uses paced session with post-send cover; residual: initial TCP+handshake still visible once per session.
2. ~~**Admission rate limits** + M-of-N consortium signatures; initial reputation **below** guard floor until vetting period.~~ **Done:** rate limits + `PROBATIONARY` admission seeding + `ThresholdConsortium` / `admit_threshold_signed` (2026-07-17).
3. ~~**Roster↔KEM key binding** in signed admission record.~~ **Done (2026-07-17):** `RelayRecord::kem_public_commitment` signed in canonical admission bytes; verify with `binds_kem_public` at path-build. **Done (2026-07-17):** production path builders [`build_bound_path_pruned`](../../crates/aegis-topology/src/path.rs) + [`hops_from_bound_path`](../../crates/aegis-client/src/send.rs) attach commitments; [`build_packet_require_bindings`](../../crates/aegis-client/src/send.rs) / CLI default `--require-kem-binding` enforce required bindings. **Done (2026-07-17):** `RelayId::from_kem_commitment` + strict signed-admit id↔commitment check (`require_kem_derived_id`, default true). **Done (2026-07-17):** `BuildPacketOptions::default()` requires KEM binding; legacy loose mode via `BuildPacketOptions::legacy_dev()` only. Residual: wire/config ids outside topology helpers may still use opaque bytes.
4. Link-layer **mutual auth** or Noise handshake derived from roster keys. **Partial/Mitigated (2026-07-17):** LegacyPsk path retains ephemeral X25519 + PSK MAC with roster `RelayId` / optional KEM commitment binding. **Optional Noise_IK-compatible** mutual auth (`LinkHandshakeMode::Noise`, feature `noise-link`) verifies peer static public against roster hex (`noise_static_public`); ops: `docs/ops/noise_link_auth.md`. Residual: not full Noise/`snow`/BLAKE2s; default remains LegacyPsk; ingress still shared static/PSK.
5. Export **coarse-grained** metrics only via [`RelayHandle::coarse_stats`]; keep [`RelayHandle::debug_stats`] in-process. ~~Avoid per-error-type telemetry visible to external GPA.~~ **Done (2026-07-17):** `RelayCoarseStats` + documented `debug_stats` boundary.
6. ~~Constant-time replay cache or epoch-shortening under load (see crypto review).~~ **Done (2026-07-17):** epoch/generation advance under flood + CT FIFO scan in `ReplayCache::ct_contains`. Residual: O(capacity) CPU per check; no `dudect` proof.
7. ~~Wire `AnomalyDetector` to admission/pruning decisions.~~ **Partial (2026-07-17):** `RelayPruningPolicy` demotes on anomaly; path/guard `*_pruned` selection + [`build_bound_path_pruned`](../../crates/aegis-topology/src/path.rs) use `is_eligible`; admission gating **Done** via [`RelayRoster::admit_signed_pruned`](../../crates/aegis-topology/src/roster.rs) / [`admit_threshold_signed_pruned`](../../crates/aegis-topology/src/roster.rs). [`PeerHealthTracker`](../../crates/aegis-relay/src/peer_health.rs) feeds metrics (`aegis-node` every 30s). **Partial (2026-07-17):** signed [`PeerHealthAdvert`](../../crates/aegis-relay/src/health_gossip.rs) over hop links (`Command::PeerHealthAdvert`, neighbor-only, half-weight) — see [`docs/ops/health_gossip.md`](ops/health_gossip.md). Residual: no global/BFT consensus; callers must use pruned APIs; unidentified inbound not attributed.
8. ~~Relay-side timestamp instrumentation for shapeability at **post-shaping** vantage (Phase 8 notes §4 future work).~~ **Done (2026-07-17):** optional `trace.path` in `aegis-node` TOML → [`RelayForwardTrace`](../../crates/aegis-relay/src/trace.rs) appends `(unix_secs_f64, cell_count, event_type)` after forward/cover/exit on the link bridge. Sample at `sim/data/relay_forward_trace_sample.csv`; loader in `sim/aegis_sim/traffic.py`. Residual: full paced multi-process re-capture not yet committed; mix relays should keep trace off.
9. **KEM seed at-rest protection** — OS keychain / encrypted store for relay KEM seeds. **Partial / Mitigated (2026-07-17):** separate seed file + Windows DPAPI (`kem-dpapi`) + Unix `keyring` (`kem-keyring`, service `aegis-node`) with pointer magic + `0600` fallback + explicit `allow_plaintext_kem` for inline TOML. Residual: same-user keychain/DPAPI (not HSM); Unix plaintext-at-rest only when keychain backend unavailable.

---

## Profiling complete (2026-07-17)

Actionable call-site gaps from the implementation-level threat model and crypto
constant-time review are **closed**. The follow-on **research/ops wave** is also
**shipped as Partial/Mitigated** (see
[`AEGIS_research_ops_hardening_plan.md`](AEGIS_research_ops_hardening_plan.md)
and `docs/ops/*`). Honest leftovers (hardware TEE SDK, BFT consensus, full AC,
BLAKE2s-Noise byte compat, WSL dudect) remain documented below — not unfinished
product wiring:

| Residual | Category | Notes |
|----------|----------|-------|
| Real TEE attestation | research | **Partial (2026-07-17)** — `AttestationProvider` + software lab quotes; hardware SGX/SEV plug-in documented in `docs/ops/tee_attestation.md` |
| Consortium authority key ceremony / PKI | ops | **Partial** — runbook `docs/ops/consortium_key_ceremony.md` + `aegis-ceremony` helper; residual: no HSM/Shamir MPC |
| Full Noise or roster-key-derived link auth | research | **Partial/Mitigated (2026-07-17)** — optional Noise_IK-compatible + roster static verify (`noise-link`); default LegacyPsk; not BLAKE2s/`snow` |
| OS keychain / encrypted KEM seed store | ops | **Partial / Mitigated** — Windows DPAPI + Unix `kem-keyring`; residual: same-user backends; Unix `0600` fallback when keychain absent |
| Ingress flood unbounded into mix queue | mitigated | **Per-conn + default global budget done** — ≈1/τ per conn + 8/τ aggregate; residual: after handshake, open TCP, mis-tuned caps |
| Cover-burst timing indistinguishability from real bulk | Partial | **τ-paced cover egress done** (default 0.35s); residual: multi-hop Sphinx semantics still differ |
| Cross-relay health gossip / reputation consensus | research | **Partial (2026-07-17)** — signed `PeerHealthAdvert` over links (`docs/ops/health_gossip.md`); residual: no global/BFT consensus |
| ZK anonymous reputation (hide relay identity) | research | **Partial** — anonymous presentation + nullifier API; full AC / consensus issuer deferred (`docs/ops/anonymous_reputation.md`) |
| Adversarial clients ignoring paced APIs | deployment | Default CLI + `PacedSession` shaped; raw API deprecated |
| Sybil plateau under majority layer-1 flood | Partial/Mitigated | Admission + g=3+rep block fresh Sybils; residual: unfiltered APIs saturate (honest science) |
| g=1 effective guard vs paper g=3 plateau | Mitigated | `GUARD_SET_SIZE=3` + production multi-guard helpers; sticky primary is intentional entry pin |
| Replay cache O(capacity) CPU / full `dudect` | research | CT FIFO scan + in-tree hit/miss smoke; full `dudect` is WSL/ops (`docs/ops/constant_time_ci.md`) |
| MAC-verify branch timing after `ct_eq` | research | Documented in constant-time review; not byte-comparison leak |
| Weighted fair queues (WFQ) | research/ops | **Partial/Mitigated** — per-connection inbound queues + equal-weight RR drain; not weighted WFQ; outbound still shared |

Re-verify: `cargo test -p aegis-topology`, `cargo test -p aegis-client -p aegis-crypto`, `cd sim && PYTHONPATH=. pytest -q`.

---

## Verification

- `cargo test -p aegis-topology` — includes `sybil_admission` integration tests (+5 tests; +8 roster threshold/KEM unit tests).
- `cargo test -p aegis-node --test trace_capture -- --ignored` — regenerates malicious CSV.
- `cd sim && PYTHONPATH=. pytest -q` — includes `test_malicious_trace.py`.
