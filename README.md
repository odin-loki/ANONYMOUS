# AEGIS

A metadata-hiding transport for a **permissioned multi-party consortium** — hides
*who talks to whom, when, and how much* against a nation-state global passive
adversary. Content encryption is assumed solved; AEGIS protects the traffic
pattern, which is what content crypto leaks. Its killer capability is **op-tempo
denial**: the wire is a flat, constant, relationship-opaque wall regardless of
underlying activity.

> **Read first:** `docs/AEGIS_SPEC_v3_consolidated.md` — the single source of truth.
> It supersedes the rest of `docs/`, which is the design history (kept for
> provenance). Every quantitative claim traces to a simulation in the spec's
> §12 evidence ledger, and each claim is tagged tested / reasoned / open.

## Governing principle
**Nothing is done until an attack simulation confirms it.** Throughout the design,
intuition was wrong repeatedly and only measurement was trustworthy. So the repo is
built around a measuring rig (`sim/`), and every implementation phase has a hard
red-team gate.

## Layout
```
docs/     the spec (start with AEGIS_SPEC_v3_consolidated.md) + design history
sim/      Python traffic-analysis harness + regression suite (the evidence ledger)
crates/   Rust workspace (the datapath), one crate per build phase
```

## The two planes (architecture in one breath)
- **Mode 1 (shaped mixnet):** small/bursty data + ALL control. Sphinx packets,
  constant-rate emission, hard-cap receiver padding, stratified L=4 topology,
  stable vetted layered guards. The command/coordination graph is hidden here at
  full strength — the crown jewel.
- **Mode 2 (bulk plane):** large files, negotiated per-transfer with a security
  **dial** (raw → bucketed → uniform+batched). Bulk relationship-hiding is not
  free; it has a size ceiling `F_max = cover_budget × round_period`.
- **Negotiator:** a protocol (not a server), end-to-end over Mode 1. Its key job is
  the batched-bulk-round scheduler that manufactures the bulk anonymity set.

## Quick start
```bash
# 1. Run the evidence ledger (the regression suite). This reproduces the red-team.
cd sim && pip install -r requirements.txt && PYTHONPATH=. pytest -q

# 2. Build and test the full datapath workspace.
cd ../crates && cargo build --workspace && cargo test --workspace
```

## Build plan (each phase = a session with a hard gate; see spec §10)
| Phase | Crate / target                        | Gate | Status |
|------:|----------------------------------------|------|--------|
| 0 | (paper)                                    | parameter budget self-consistent | **done** |
| 1 | `sim/`                                      | reproduces evidence ledger | **done** (23/23 pytest, incl. Phase-8 hardening + real/malicious-trace tests) |
| 2 | `aegis-crypto`                              | Sphinx test vectors: replay/tamper/const-size/KAT | **done** (36/36) — see `docs/AEGIS_phase2_implementation_notes.md` for the packet layout, `docs/AEGIS_crypto_constant_time_review.md` for the security-profiling pass (real libFuzzer via WSL — 4 targets, up to 1.17M execs each, 0 crashes — plus constant-time review and `cargo audit`, both clean); real Sphinx↔Cell fragmentation (`fragment.rs`) and a bounded FIFO `ReplayCache` are implemented |
| 3 | `aegis-relay`, `-topology`, `-node`         | testnet routes Sphinx e2e; latency matches budget | **done** (14/14 + 41/41 + 4/4) — real TCP link transport with an ephemeral X25519 forward-secrecy handshake per connection (`aegis-relay/src/net.rs`, `aegis-crypto/src/link.rs`), read-timeout + connection-cap DoS hardening, and a runnable `aegis-node` relay binary; 4-hop testnet (in-process and real-socket, including the paced send path) measures e2e latency on target for the §7 ~2s mixing mean |
| 4 | `aegis-client`                              | live traffic vs intersection+confirmation → baseline (**= the sales demo**) | **done** (14/14) — `tests/surge_demo.rs` is the literal LEFT/RIGHT-pane demo artifact from §11; the `aegis-client` binary now defaults to a genuinely τ-paced constant-rate send (`send_payload_paced`, one real Sphinx fragment per tick over a real TCP link) instead of an instantaneous burst, with `--raw` kept as an explicit escape hatch for trace capture |
| 5 | guards/beacon/admission                     | guard-exposure sim matches vetted-c plateau (~3%) | **done** — folded into `aegis-topology` (`guards`, `roster`, `beacon`); roster admission is ed25519-signed with disk persistence, rate-limited (default 5 admissions / 24h), and seeds new relays at a probationary reputation floor rather than neutral trust; the beacon is a real threshold-BLS distributed randomness beacon (`blsttc`) |
| 6 | `aegis-negotiator`                          | bulk correlation/confirmation at target dial bounds | **done** (25/25) — dial/F_max/rendezvous/scheduler logic reconciled against `sim/`'s numeric ground truth; its cover-flow math is now wired into `aegis-relay` (`cover_flow.rs`) so a relay can synthesize L2 bulk cover flows at round boundaries |
| 7 | trust/attestation                           | core gates hold with TEE assumed broken | **partial** — `aegis-trust` ships a real reputation ledger + anomaly detector (26/26), a genuine Bulletproofs zero-knowledge range proof for reputation thresholds, and reputation-aware guard/path selection in `aegis-topology` that a Sybil-admission simulation shows collapses rep-filtered path capture from ~45% to 0% at a 50% flood; real TEE attestation remains an explicit deferred interface boundary |
| 8 | hardening                                   | real-trace shapeability; documented ε per tier | **done** — a benign client-send trace and a malicious/flooding trace, both captured from the real Sphinx/TCP testnet, were run through `shapeability_report` and compared against each other and the synthetic stand-in; see `docs/AEGIS_phase8_hardening_notes.md` §4 |

All of the above is independently re-verifiable with `cd sim && PYTHONPATH=. pytest -q` (**25 passed**) and `cd crates && cargo test --workspace` (**195 passed, 3 ignored, 0 failed**, plus `cargo deny check` clean, `.github/workflows/ci.yml` for test/deny/nightly fuzz-smoke, and a workspace-wide `unsafe_code = forbid` lint policy — see `docs/AEGIS_implementation_threat_model.md`).

## Security profiling
Beyond the phase gates above, a dedicated security-profiling pass (real fuzzing + a real implementation-level threat model, not just the paper design) lives across:
- `docs/AEGIS_crypto_constant_time_review.md` — constant-time review + real `cargo-fuzz`/libFuzzer results (via WSL; Windows lacks libFuzzer sanitizer support) for `aegis-crypto`'s attacker-facing parsers, plus `aegis-topology`'s roster/beacon deserialization.
- `docs/AEGIS_implementation_threat_model.md` — STRIDE pass on the real code; actionable call-site gaps closed (**Profiling complete**). Residuals are research/ops (ZK anonymous reputation, TEE, Noise, etc.); ingress rate-limit + DPAPI are among the done mitigations — see that doc's table.
- `crates/aegis-topology/tests/sybil_admission.rs` — a real Sybil-admission simulation against the actual roster/reputation code, with measured before/after numbers.
- `sim/data/real_testnet_malicious_trace.csv` + `sim/scripts/analyze_malicious_trace.py` — a flooding/adversarial trace capture compared against the benign trace and synthetic stand-in.
- `crates/deny.toml` — supply-chain policy (`cargo deny check`: advisories/licenses/bans/sources), enforced alongside a workspace-wide Clippy security lint set (`unsafe_code = forbid`, warn on `unwrap_used`/`expect_used`/`indexing_slicing`/`arithmetic_side_effects`).

## Where to start in Cursor
1. Skim `docs/AEGIS_SPEC_v3_consolidated.md` (esp. §4, §5, §6, §10, §12).
2. Run the `sim/` suite so the evidence ledger is live in your session.
3. Run `cargo test --workspace` in `crates/` — Phases 2–8 are implemented; see each
   crate's module docs, `docs/AEGIS_phase2_implementation_notes.md`,
   `docs/AEGIS_crypto_constant_time_review.md`, `docs/AEGIS_implementation_threat_model.md`,
   and `docs/AEGIS_phase8_hardening_notes.md` for concrete design decisions and honestly
   which claims are [T]/[R]/[O] at the implementation (not just simulation) level.
4. Try the real testnet: `cargo run -p aegis-node -- --config <toml>` for one or more
   relays, then `cargo run -p aegis-client -- --config <toml>` to send a real, τ-paced
   Sphinx packet over TCP (see `crates/aegis-node/tests/tcp_testnet.rs` for a runnable
   example of the config shape). `crates/aegis-node/tests/trace_capture.rs` (run with
   `-- --ignored`) reproduces the Phase-8 benign and malicious real trace captures.

   **Security profiling status (2026-07-17): done** for actionable call-site gaps.
   Mitigations include paced session + ρ≤0.7, ingress token-bucket rate limit,
   M-of-N + KEM-derived `RelayId`, CT replay scan, signed reputation snapshots,
   link FS + roster-id/KEM handshake binding, required L2 bulk cover,
   peer-health→EWMA, anomaly-gated admission, verified roster load, external
   KEM seeds (Windows DPAPI-protected by default), exit sink, post-shaping
   traces, deprecated raw `send_payload`, default-required KEM bindings,
   drop-newest bounded queues, CI fuzz/deny.

   Accepted residuals (ops / research, not unfinished wiring): real TEE attestation;
   consortium key ceremony; full Noise / roster-key-derived link auth; Unix
   keychain KEM encryption; cover-burst timing indistinguishability; cross-relay
   health gossip / reputation consensus; ZK anonymous reputation; multi-connection
   ingress floods up to connection cap; Sybil plateau under majority flood;
   g=1 vs g=3 guard exposure. See **Profiling complete** in
   `docs/AEGIS_implementation_threat_model.md`.

## Honest boundaries (do not oversell — see spec §8, §9)
- Strong guarantees are for **internal** (client↔client) traffic. Clearnet exit is
  weaker. Bulk relationship-hiding is tunable and bounded, not free.
- Results are **empirical bounds** under the stated adversary model, not proofs.
- Not interactive; multi-second latency is inherent.
- A mixnet is the **wrong tool** for two-party op-tempo hiding (use link-layer
  traffic-flow security). AEGIS earns its keep only for many-endpoint
  relationship-graph hiding against a global passive adversary.
