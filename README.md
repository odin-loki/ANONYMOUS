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
| 1 | `sim/`                                      | reproduces evidence ledger | **done** (19/19 pytest, incl. Phase-8 hardening + real-trace tests) |
| 2 | `aegis-crypto`                              | Sphinx test vectors: replay/tamper/const-size/KAT | **done** (29/29) — see `docs/AEGIS_phase2_implementation_notes.md` for the packet layout, `docs/AEGIS_crypto_constant_time_review.md` for the security-profiling pass (40k-iteration proptest fuzzing, constant-time review, `cargo audit` — clean); real Sphinx↔Cell fragmentation (`fragment.rs`) and a bounded FIFO `ReplayCache` are implemented |
| 3 | `aegis-relay`, `-topology`, `-node`         | testnet routes Sphinx e2e; latency matches budget | **done** (10/10 + 34/34 + 3/3) — real TCP link transport (`aegis-relay/src/net.rs`) with a runnable `aegis-node` relay binary; 4-hop testnet (in-process and real-socket) measures e2e latency on target for the §7 ~2s mixing mean |
| 4 | `aegis-client`                              | live traffic vs intersection+confirmation → baseline (**= the sales demo**) | **done** (10/10) — `tests/surge_demo.rs` is the literal LEFT/RIGHT-pane demo artifact from §11; `aegis-client` binary now builds/fragments/sends real Sphinx packets over TCP to a live `aegis-node` |
| 5 | guards/beacon/admission                     | guard-exposure sim matches vetted-c plateau (~3%) | **done** — folded into `aegis-topology` (`guards`, `roster`, `beacon`); roster admission is ed25519-signed with disk persistence, and the beacon is a real threshold-BLS distributed randomness beacon (`blsttc`), not the earlier hash-chain stand-in |
| 6 | `aegis-negotiator`                          | bulk correlation/confirmation at target dial bounds | **done** (25/25) — dial/F_max/rendezvous/scheduler logic reconciled against `sim/`'s numeric ground truth; its cover-flow math is now wired into `aegis-relay` (`cover_flow.rs`) so a relay can synthesize L2 bulk cover flows at round boundaries |
| 7 | trust/attestation                           | core gates hold with TEE assumed broken | **partial** — `aegis-trust` ships a real reputation ledger + anomaly detector, a genuine Bulletproofs zero-knowledge range proof for reputation thresholds (replacing the earlier plaintext stand-in), and reputation-aware guard/path selection in `aegis-topology`; real TEE attestation remains an explicit deferred interface boundary |
| 8 | hardening                                   | real-trace shapeability; documented ε per tier | **done** — a genuine client-send trace captured from the real Sphinx/TCP testnet (`sim/data/real_testnet_trace.csv`) was run through `shapeability_report` and compared to the synthetic stand-in; see the new §4 of `docs/AEGIS_phase8_hardening_notes.md` |

All of the above is independently re-verifiable with `cd sim && PYTHONPATH=. pytest -q` and `cd crates && cargo test --workspace`.

## Where to start in Cursor
1. Skim `docs/AEGIS_SPEC_v3_consolidated.md` (esp. §4, §5, §6, §10, §12).
2. Run the `sim/` suite so the evidence ledger is live in your session.
3. Run `cargo test --workspace` in `crates/` — Phases 2–8 are implemented; see each
   crate's module docs, `docs/AEGIS_phase2_implementation_notes.md`,
   `docs/AEGIS_crypto_constant_time_review.md`, and `docs/AEGIS_phase8_hardening_notes.md`
   for concrete design decisions and honestly which claims are [T]/[R]/[O] at the
   implementation (not just simulation) level.
4. Try the real testnet: `cargo run -p aegis-node -- --config <toml>` for one or more
   relays, then `cargo run -p aegis-client -- --config <toml>` to send a real Sphinx
   packet over TCP (see `crates/aegis-node/tests/tcp_testnet.rs` for a runnable example
   of the config shape). `crates/aegis-node/tests/trace_capture.rs` (run with
   `-- --ignored`) reproduces the Phase-8 real trace capture.

   Remaining real work: real TEE attestation for Phase 7, wiring cover-flow bursts
   from `aegis-relay` onto the outbound wire (currently accounted for at the library
   level only), multi-process testnet orchestration (the committed real trace used the
   in-process fallback — multi-process port/peer-routing had orchestration issues),
   and running `cargo-fuzz` for real on Linux/macOS CI (Windows lacks libFuzzer
   sanitizer support here, so `aegis-crypto` currently falls back to 40k-iteration
   `proptest` harnesses covering the same attack surface).

## Honest boundaries (do not oversell — see spec §8, §9)
- Strong guarantees are for **internal** (client↔client) traffic. Clearnet exit is
  weaker. Bulk relationship-hiding is tunable and bounded, not free.
- Results are **empirical bounds** under the stated adversary model, not proofs.
- Not interactive; multi-second latency is inherent.
- A mixnet is the **wrong tool** for two-party op-tempo hiding (use link-layer
  traffic-flow security). AEGIS earns its keep only for many-endpoint
  relationship-graph hiding against a global passive adversary.
