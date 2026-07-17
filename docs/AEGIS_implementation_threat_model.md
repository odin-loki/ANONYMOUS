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
| 1 | **`send_payload` / legacy paced send go quiet after 18 ticks** — unpaced burst and one-shot paced path expose true cadence at client TCP ingress. **Partial (2026-07-17):** default CLI uses `PacedSession` with continuous dummy cover + connection reuse; `--raw` and `send_payload` remain for trace capture. | `aegis-client::send`, `aegis-client::session`, CLI `--raw` | **Medium** (was High for default path) |
| 2 | **~~No admission rate limit~~** — ~~compromised consortium signing key ⇒ unlimited signed Sybil relays; fresh Sybils get NEUTRAL reputation (0.5) and pass the 0.3 floor immediately.~~ **Mitigated (2026-07-12):** probationary admission reputation (0.1) + configurable rate limit (default 5/24h). **Mitigated (2026-07-17):** M-of-N threshold admission (`ThresholdConsortium` / `admit_threshold_signed`). Residual: consortium key ceremony out of band; reputation `update()` wiring. | `aegis-topology::roster`, `aegis-trust::reputation` | **Low–medium** (was High) |
| 3 | **Hop link PSK + ephemeral handshake (partial roster binding)** — per-TCP X25519 ECDH derives fresh session keys (forward secrecy); static PSK authenticates the handshake via keyed MAC. **`LinkBridgeConfig::identity_binding`** (default true) binds confirm/finish MACs to the peer roster `RelayId` so a stolen PSK for peer A cannot authenticate as peer B. Residual: PSK still in config/TOML; no Noise or roster-key-derived auth; optional KEM commitment not wired on hop links; ingress accepts any holder of the shared ingress key who knows the first-hop id. | `aegis-crypto::link`, `aegis-relay::net`, `aegis-node::config` | **Low–medium** (was Medium) |
| 4 | **Relay error/load counters observable** — fine-grained per-error counters remain available via [`RelayHandle::debug_stats`] for in-process tests only; external surfaces must use [`RelayHandle::coarse_stats`] (aggregated buckets). Residual GPA risk if coarse buckets are scraped at high frequency under flood. | `aegis-relay::node::RelayCoarseStats` | **Low–medium** (was Medium) |
| 5 | **Replay cache eviction under sustained flood** — **Partial (2026-07-17):** generation/`advance_epoch()` + proactive shorten at 85% fill on large caches. Residual: `HashSet` membership not constant-time; shortened window under flood is intentional trade-off. | `aegis-crypto::replay` | **Low–medium** (was Medium) |

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
| `ReplayCache::check_and_insert` uses `HashSet::contains` (not constant-time). | `replay.rs:64–66` | **Open gap** — see constant-time review §2 out-of-scope note. | Low–medium |
| Fixed packet size regardless of path length. | `SphinxPacket`, `SPHINX_PACKET_LEN` | **Mitigated**. | — |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Bounded replay cache with generation advance under flood. | `replay::ReplayCache::with_capacity`, `advance_epoch` | **Partial (2026-07-17)** — proactive generation advance at 85% fill shortens window under load; epoch rollover remains primary defense. Residual: CT `HashSet` lookup. | **Low–medium** (was Medium) |
| `process()` on arbitrary bytes returns errors without panic (proptest/fuzz gate). | `sphinx::process`, `tests/parser_fuzz_properties.rs` | **Mitigated**. | — |
| Large fixed packets (8504 B Sphinx + 18 fragments) — CPU/memory per flood packet. | `fragment`, `sphinx` | **Partial** — no explicit rate limit in crate. | Low |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No privilege model in crate; relay secret only peels one layer. | `sphinx::process` | **Mitigated** — cannot skip layers without keys. | — |

**Overall:** Crypto core matches Phase-2 gate properties. Residual issues are replay-cache timing/eviction and link-layer auth (delegated to deployment). **Do not re-audit constant-time details here** — see `AEGIS_crypto_constant_time_review.md`.

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
| Cover flows are emitted as [`Command::SphinxFragment`] bursts on hop links (AEAD-sealed, same frame width as real bulk). Reserved-byte marker `COVER_FRAGMENT_RESERVED` prevents inbound reassembly/peel; cover never enters the Sphinx forward path. Residual: inter-cell timing and multi-hop semantics differ from genuine bulk. | `cover_flow.rs`, `node.rs` cover channel, `net.rs` cover dispatcher | **Partial** — wire volume/count padded; timing/shape GPA still possible. |
| `RelayCoarseStats` exposes only aggregated `processed_ok` / `processed_fail` / `cover_emitted` for external export. Fine-grained per-error counters live in [`RelayHandle::debug_stats`] (documented internal-only). | `node::RelayCoarseStats`, `node::RelayDebugStats` | **Mitigated** for external metrics — do not export `debug_stats`. Residual if coarse buckets scraped under flood. | Low–medium |
| `ForwardedPacket::delay_applied` records delay (internal struct). | `node::ForwardedPacket` | Low risk unless logged. | Low |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Inbound/outbound `mpsc` channels (capacity 64 in testnet). | `trace_capture.rs`, `node::spawn` | **Partial** — backpressure blocks senders; no fair queue drop policy documented. | Medium |
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
| `RelayId::from_u64` is placeholder — not PK-derived from KEM keys. | `types::RelayId` | **Partial** — signed admission now binds SHA3-256 KEM commitment (`RelayRecord::kem_public_commitment`, `binds_kem_public`); id field still opaque until PK-derived ids land. | Low–medium |
| Signed admission binds id + jurisdiction + KEM commitment via ed25519. | `roster::admit_threshold_signed`, `RelayRecord::binds_kem_public` | **Mitigated** when production path used; path builders must call `binds_kem_public` before encapsulation. | — |
| Test-only `RelayRoster::admit()` skips signature. | `roster.rs:105–117` | **Open gap** if used in prod — explicitly documented test-only. | High if misused |

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
| Stable guard fixed for epoch — GPA learns entry guard identity for that client epoch. | `guards::GuardSelector::primary_guard` | **By design** — exposure bounded by plateau math if `c` small. | informational |
| **Implementation uses only `primary_guard()` (g=1 effective), not rotation across held g=3** — paper ~3% plateau assumes `1-(1-c)^g`; code exposure ≈ `c` at layer 1. | `guards::GuardSelector::primary_guard`, `path::select_path` L74–76 | **Gap vs paper sim** — lower exposure at small c, but Sybil flood still dominates. | Medium |
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
| Sybil flood raises guard capture to `1-(1-c)^g` with `c` = layer-1 Sybil fraction — matches formula but **breaks** vetted `c≈1%` assumption when the honest pool fails. **Separate from admission mitigations** (rate limit 5/24h, probation 0.1, M-of-N threshold, rep-filtered paths): those block **fresh** Sybils, but unfiltered `primary_guard()` still tracks layer-1 Sybil share at majority flood. | `guards::guard_exposure_plateau`, `tests/sybil_admission.rs` | Quantified research — paper ~3% plateau holds only with honest vetted pool; admission controls do not restore plateau under 50%+ layer-1 Sybil fraction. | **High** |

**Sybil simulation summary:** See §Simulation results below.

---

## 4. `aegis-trust`

**Role:** EWMA reputation, ZK range proofs, anomaly detector, TEE bookkeeping (spec §4.8, Phase 7).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| `PlaintextReputationProof` embeds score — not ZK. | `zk::PlaintextReputationProof` | **Mitigated** by docs — production must use `BulletproofsReputationProof`. | Low if misconfigured |
| ZK proofs do not hide relay identity (module docs). | `zk.rs` L21–23 | **Open gap** for anonymous reputation. | Medium |

### Tampering

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Bulletproofs verify threshold on scaled integer. | `zk::BulletproofsReputationProof::verify` | **Mitigated** for score threshold integrity. | — |
| In-memory ledger — no persistence or consensus. | `reputation::ReputationLedger` | **Open gap** — each operator could hold different scores. | Medium |

### Repudiation

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| No signed reputation updates. | `reputation::record_success/failure` | **Open gap** — repudiation of bad behavior reports. | Low |

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
| `AnomalyDetector` → path/guard selection and **new admission** via [`RelayPruningPolicy`](../../crates/aegis-trust/src/policy.rs) `*_pruned` APIs (`admit_signed_pruned` / `admit_threshold_signed_pruned`); [`PeerHealthTracker`](../../crates/aegis-relay/src/peer_health.rs) feeds failure rates via [`feed_peer_metric`](../../crates/aegis-trust/src/policy.rs) (`aegis-node` drains every 30s). | `anomaly.rs`, `aegis-topology::{path,guards,roster}`, `aegis-relay::{peer_health,net}` | **Partial** — admission gating Done via `admit_*_pruned`; residual: callers must use pruned APIs (legacy `admit_*` unwired); no peer-health gossip. | Medium |
| `core_gates_hold_under(BrokenEnclave)` vacuously true — no TEE dependency yet. | `tee::core_gates_hold_under` | **Mitigated** (honestly documented). | — |

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
| Cover requirement is advisory — relay must call `begin_bulk_round`. | `cover.rs` vs `aegis-relay` | **Partial** — misconfigured relay skips cover. | Medium |

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
| **`send_payload` / CLI `--raw` bypass emitter** — unpaced burst at client TCP ingress; GPA sees true cadence. | `send.rs:154–183`, CLI `--raw`, `trace_capture.rs` | **Partial (2026-07-17)** — default CLI and [`PacedSession`](../../crates/aegis-client/src/session.rs) use continuous `ConstantRateEmitter` + post-send cover; raw API retained for adversarial trace capture only. Residual: one-time TCP/handshake per session; ρ not auto-enforced. | **Medium** (High if misusing raw API) |
| Hard-cap padder emits exactly Q slots per round externally. | `padding::HardCapPadder::round` | **Mitigated** when used. | — |
| Dummy cells use CSPRNG padding. | `emitter::encode_dummy_cell` | **Mitigated**. | — |

### Denial of service

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Emitter queue unbounded on `enqueue`. | `emitter::ConstantRateEmitter` | **Partial** — memory DoS if client never ticks. | Low |
| ρ > 0.7 warning via `rho_at_peak_rate` only — not enforced. | `emitter::rho_at_peak_rate` | **Open gap** — operator must configure τ. | Medium |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Malicious/custom client can bypass paced APIs and flood ingress. | `send_payload` vs [`PacedSession`](../../crates/aegis-client/src/session.rs) / CLI default | **Partial (2026-07-17)** — shipped default path wires emitter; bypass is a **deployment residual** for adversarial or mis-integrated clients, not an unfinished product default. | **Medium** (High for deliberate raw integration) |

---

## 7. `aegis-node`

**Role:** Runnable relay process — TOML config, KEM persistence, TCP bridge (spec §10 Phase 3).

### Spoofing

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| Peer table from config file — wrong peer addr ⇒ misroute. | `config::NodeConfigFile`, `main.rs` | **Mitigated** by ops; no runtime discovery. | Low |
| KEM seeds written to disk on first run. | `config::load_or_init_kem` | **Open gap** — plaintext seeds in TOML unless externally encrypted. | Medium |

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
| mpsc(64) channels — same as relay. | `main.rs:47–48` | **Partial**. | Medium |
| Multi-process testnet had peer routing failures (Phase 8 notes). | `sim/scripts/capture_multiprocess_trace.py` | **Open gap** for standalone deployment. | Medium |

### Elevation of privilege

| Finding | Location | Status | Sev |
|---------|----------|--------|-----|
| `--mu` CLI override without auth. | `main.rs:36–37` | Local operator only. | Low |

---

## Simulation-backed findings

### A. Sybil admission (`sybil_admission.rs`)

**Methodology:** 24 honest + N attacker-signed Sybils via real `admit_signed` (with shared `ReputationLedger`); `build_topology` + `GuardSelector` + `select_path*`; 2000 client seeds; compare to `guard_exposure_plateau(c, g=3)`. Honest relays seeded with 30 EWMA successes above the 0.3 floor; Sybils start at `PROBATIONARY` (0.1) via `admit_new_relay`.

| Scenario | Layer-1 Sybil fraction | Primary-guard Sybil rate | Rep-filtered path Sybil rate | Paper ~3% plateau |
|----------|------------------------|--------------------------|------------------------------|-------------------|
| 0 Sybils (baseline) | 0% | ~0% | ~0% | — |
| 1 Sybil / 100 relays (c≈1%) | ~1% | **~1.0%** | **~0%** (was ~1% pre-fix with NEUTRAL Sybil) | ~2.97% |
| 24 + 24 Sybils (50% flood) | ~67% | **~67%** (unchanged — topology) | **~0%** (was **~45%** pre-fix) | >> 3% |
| 24 + 96 Sybils (80% flood) | ~67% | **~66%** | **~0%** (was ~90%+ unfiltered) | >> 3% |
| Rate-limited: 24 honest + 5 Sybils/window | ~0% | **~0%** | **~0%** (was unbounded 500 Sybils/admit batch) | — |

**Fix (2026-07-12):** `ReputationScore::PROBATIONARY` (0.1) seeded at signed admission; `RosterAdmissionPolicy` default **5 admissions / 24h** (`AdmissionRateLimitExceeded`). Reputation-filtered path/guard selection now excludes fresh Sybils. **Fix (2026-07-17):** M-of-N threshold admission (`ThresholdConsortium`, default production path `admit_threshold_signed`); signed roster records include SHA3-256 hybrid KEM public-key commitments verified via `RelayRecord::binds_kem_public`. **Residual risk:** consortium authority key ceremony remains out of band; probation only effective when callers use reputation-aware `select_path*` / `new_reputation_weighted` with a ledger that received `admit_signed`/`admit_threshold_signed` seeding; unfiltered `select_path` / primary guard still tracks layer-1 Sybil fraction; `record_success`/`record_failure` wiring from live relays not yet automatic; path builders must enforce KEM binding at encapsulation time.

**Conclusion:** The **closed-form plateau math exists** (`guard_exposure_plateau`) but **path selection uses only the primary guard**, so empirical exposure ≈ layer-1 Sybil fraction, not the g=3 paper plateau. The **vetted ~3% claim applies to the Python evidence-ledger model**, not literally to `select_path(..., Some(&guards))` today. **Admission rate limit** caps roster growth to 5 new relays per 24h per roster instance. **Reputation filtering blocks fresh Sybils** at the 0.3 floor when the shared ledger is wired through admission.

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

**Behavior:** Raw `send_payload` (and CLI `--raw`) bypass `ConstantRateEmitter` and bulk negotiator/cover-flow — the flood is **not shaped**. Default paced CLI would emit τ-shaped cells + dummy cover instead. Relays **accept all packets** at this load (no client errors, no ingress drops); degradation manifests as **queueing/mixing delay** (not captured in client-send CSV). **Side-channel (raw path only):** sustained high `events_per_slot_max` (12 vs 4) is directly observable to a GPA at client ingress; relay processing latency under load vs idle is a residual if metrics or timing are visible (see `RelayCoarseStats`; post-shaping traces in Future work §8).

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
- Honest bulk cover limitations documented (`aegis-relay::cover_flow`); cover bursts wired on hop links via cover outbound channel (`aegis-relay::net`)

---

## Future work (implementation)

1. Wire **mandatory** `ConstantRateEmitter` on all client egress via [`PacedSession`](../../crates/aegis-client/src/session.rs) (continuous dummy cover + one TCP link per session); keep raw `send_payload` / `--raw` for adversarial trace capture only. **Done (2026-07-17):** CLI default uses paced session with post-send cover; residual: initial TCP+handshake still visible once per session.
2. ~~**Admission rate limits** + M-of-N consortium signatures; initial reputation **below** guard floor until vetting period.~~ **Done:** rate limits + `PROBATIONARY` admission seeding + `ThresholdConsortium` / `admit_threshold_signed` (2026-07-17).
3. ~~**Roster↔KEM key binding** in signed admission record.~~ **Done (2026-07-17):** `RelayRecord::kem_public_commitment` signed in canonical admission bytes; verify with `binds_kem_public` at path-build. **Partial (2026-07-17):** production path builders [`build_bound_path_pruned`](../../crates/aegis-topology/src/path.rs) + [`hops_from_bound_path`](../../crates/aegis-client/src/send.rs) attach commitments; [`build_packet_require_bindings`](../../crates/aegis-client/src/send.rs) / CLI `--require-kem-binding` enforce required bindings. Residual: `RelayId` still opaque placeholder; legacy `build_packet` still allows missing commitments.
4. Link-layer **mutual auth** or Noise handshake derived from roster keys. **Partial (2026-07-17):** ephemeral X25519 + PSK MAC with roster `RelayId` binding (`LinkHandshakeBinding`, `LinkBridgeConfig::identity_binding`). Residual: full Noise / roster-key-derived auth; optional KEM commitment in MAC not wired from node config; ingress still shared-key.
5. Export **coarse-grained** metrics only via [`RelayHandle::coarse_stats`]; keep [`RelayHandle::debug_stats`] in-process. ~~Avoid per-error-type telemetry visible to external GPA.~~ **Done (2026-07-17):** `RelayCoarseStats` + documented `debug_stats` boundary.
6. Constant-time replay cache or epoch-shortening under load (see crypto review). **Partial (2026-07-17):** epoch/generation advance under flood. Residual: CT `HashSet` lookup still open.
7. ~~Wire `AnomalyDetector` to admission/pruning decisions.~~ **Partial (2026-07-17):** `RelayPruningPolicy` demotes on anomaly; path/guard `*_pruned` selection + [`build_bound_path_pruned`](../../crates/aegis-topology/src/path.rs) use `is_eligible`; admission gating **Done** via [`RelayRoster::admit_signed_pruned`](../../crates/aegis-topology/src/roster.rs) / [`admit_threshold_signed_pruned`](../../crates/aegis-topology/src/roster.rs) (reject new admissions when candidate fails `is_eligible`; seed reputation on policy ledger). [`PeerHealthTracker`](../../crates/aegis-relay/src/peer_health.rs) / [`drain_into_policy`](../../crates/aegis-relay/src/peer_health.rs) feed metrics (`aegis-node` every 30s). `aegis-node` has no live roster-admission path — production callers must use `admit_*_pruned`. Residual: callers must use pruned APIs (legacy `admit_*` for tests/dev); no peer-health gossip; inbound handshake failures not keyed to peer id.
8. ~~Relay-side timestamp instrumentation for shapeability at **post-shaping** vantage (Phase 8 notes §4 future work).~~ **Done (2026-07-17):** optional `trace.path` in `aegis-node` TOML → [`RelayForwardTrace`](../../crates/aegis-relay/src/trace.rs) appends `(unix_secs_f64, cell_count, event_type)` after forward/cover/exit on the link bridge. Sample at `sim/data/relay_forward_trace_sample.csv`; loader in `sim/aegis_sim/traffic.py`. Residual: full paced multi-process re-capture not yet committed; mix relays should keep trace off.

---

## Verification

- `cargo test -p aegis-topology` — includes `sybil_admission` integration tests (+5 tests; +8 roster threshold/KEM unit tests).
- `cargo test -p aegis-node --test trace_capture -- --ignored` — regenerates malicious CSV.
- `cd sim && PYTHONPATH=. pytest -q` — includes `test_malicious_trace.py`.
