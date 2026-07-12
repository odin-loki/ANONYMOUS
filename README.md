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
| Phase | Crate / target        | Gate | Status |
|------:|-----------------------|------|--------|
| 0 | (paper)                   | parameter budget self-consistent | **done** |
| 1 | `sim/`                    | reproduces evidence ledger | **done** (17/17 pytest, incl. Phase-8 hardening tests) |
| 2 | `aegis-crypto`            | Sphinx test vectors: replay/tamper/const-size/KAT | **done** (11/11) — see `docs/AEGIS_phase2_implementation_notes.md` for the concrete packet layout (deviates from the illustrative "512B" figure — ML-KEM-768 alone needs more) |
| 3 | `aegis-relay`,`-topology` | testnet routes Sphinx e2e; latency matches budget | **done** (18/18 + 6/6) — 4-hop in-process testnet measures ~2.1–2.5s e2e, on target for the §7 ~2s mixing mean |
| 4 | `aegis-client`            | live traffic vs intersection+confirmation → baseline (**= the sales demo**) | **done** (10/10) — `tests/surge_demo.rs` is the literal LEFT/RIGHT-pane demo artifact from §11 |
| 5 | guards/beacon/admission   | guard-exposure sim matches vetted-c plateau (~3%) | **done** — folded into `aegis-topology` (`guards`, `roster`, `beacon` modules); beacon is a hash-chain stand-in, NOT real threshold-BLS (documented limitation, see module docs) |
| 6 | `aegis-negotiator`        | bulk correlation/confirmation at target dial bounds | **done** (25/25) — dial/F_max/rendezvous/scheduler logic implemented and reconciled against `sim/`'s numeric ground truth |
| 7 | trust/attestation         | core gates hold with TEE assumed broken | **partial** — `aegis-trust` ships a real reputation ledger + anomaly detector; ZK proof and real TEE attestation are explicit deferred interface boundaries, not faked (see crate docs) |
| 8 | hardening                 | real-trace shapeability; documented ε per tier | **partial** — tooling + adaptive-adversary quantification added (`sim/aegis_sim`, `docs/AEGIS_phase8_hardening_notes.md`); still needs a genuine trace run through it, per that doc |

All of the above is independently re-verifiable with `cd sim && PYTHONPATH=. pytest -q` and `cd crates && cargo test --workspace`.

## Where to start in Cursor
1. Skim `docs/AEGIS_SPEC_v3_consolidated.md` (esp. §4, §5, §6, §10, §12).
2. Run the `sim/` suite so the evidence ledger is live in your session.
3. Run `cargo test --workspace` in `crates/` — Phases 2–7 are implemented; see each
   crate's module docs and `docs/AEGIS_phase2_implementation_notes.md` /
   `docs/AEGIS_phase8_hardening_notes.md` for concrete design decisions and honestly
   which claims are [T]/[R]/[O] at the implementation (not just simulation) level.
   Remaining real work: a production network transport for `aegis-relay` (currently
   in-process channels), wiring `aegis-client` to it, a genuine threshold-BLS beacon,
   a real ZK reputation circuit, and running a real trace through the Phase-8 tooling.

## Honest boundaries (do not oversell — see spec §8, §9)
- Strong guarantees are for **internal** (client↔client) traffic. Clearnet exit is
  weaker. Bulk relationship-hiding is tunable and bounded, not free.
- Results are **empirical bounds** under the stated adversary model, not proofs.
- Not interactive; multi-second latency is inherent.
- A mixnet is the **wrong tool** for two-party op-tempo hiding (use link-layer
  traffic-flow security). AEGIS earns its keep only for many-endpoint
  relationship-graph hiding against a global passive adversary.
