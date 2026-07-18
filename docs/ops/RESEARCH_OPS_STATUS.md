# Research / ops residual status (one-page)

**Date:** 2026-07-18  
**Tip:** `c7c2f0d`  
**Hub:** [`RESEARCH_THEORY_AND_STATUS.md`](RESEARCH_THEORY_AND_STATUS.md)  
**Backlog:** [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md)

Legend: **Done** = in-tree as scoped · **Partial** = useful mitigation with honest leftover · **External** = B-class platform/operator — not unfinished wiring.  
**Research is not closed.**

| # | Residual | Status | In-tree (tip) | Leftover / External |
|---|----------|--------|---------------|---------------------|
| 1 | Real TEE attestation | **Partial** | Software quotes + `HardwareTeeProvider` fail-closed; DCAP/SEV types; `tee-hardware` hook | **External:** Intel DCAP / AMD SEV-SNP + device |
| 2 | Consortium key ceremony / HSM | **Partial** | Shamir + `Pkcs11CustodyOps`; SimulatedHSM; **SoftHSM2 user-local Succeeded** (S6) | **External:** vendor HSM + MPC; SoftHSM ≠ hardware |
| 3 | Noise / roster-key link auth | **Partial/Mitigated** | `handshake=auto` → Noise_IK; ingress KEM commitment fail-closed | Pre-snow peers; Noise does not bind KEM |
| 4 | Unix / keychain KEM store | **Partial** | Unix `kem-keyring` + Windows DPAPI | **External:** HSM / cross-user store |
| 5 | Cover-burst + multi-hop cover | **Partial** | τ-paced cover; CV/KS; **A3/B1** `matched_local_discard` + peelable **`cover_onions`** | Not info-theoretic; peel-to-sink ≠ client exit |
| 6 | Cross-relay health gossip | **Partial** | Quorum log + **A1 stacked** (`K=4`, `min_orgs=2`, eclipse-detect) | **External:** multi-org BFT; `f=1` saturates |
| 7 | ZK anonymous reputation | **Partial** | Issuer + blinded issue + nullifier; C4 sim | **External:** interactive AC / real ZK |
| 8 | Adversarial multi-conn flood | **Done** | Global ingress budget 8/τ | Tunable caps |
| 9 | Sybil / g=3 guard plateau | **Done** | g=3 helpers; unfiltered APIs `test-utils` only | Science tests keep unfiltered |
| 10 | dudect / CT evidence | **Partial** | Smokes + WSL deepen (not isolated) | **External:** ≥10⁵/primitive isolated CPU |
| 11 | Per-peer fair queues | **Done** | Health-weighted inbound + outbound WFQ | Discrete weight quanta |
| 12 | Emitter backlog | **Done** | Cap 256; fail send on full | — |
| 13 | Adaptive guard (§13) | **Partial** | **v1–v4**; prefer **`adaptive_v4`** (best sim Partial) | Long-E saturation; field rates; §13 [O] |
| 14 | Mode-1 combined attack | **Partial** (ops) | Hard-cap ranked best; fused_v4 sim | Not WAN closed; pad-up etc. vulnerable |
| 15 | Exit-tier / presence_pad | **Partial** | Sim defenses + **A2** `[exit].presence_pad` (default off) | Clearnet GPA |
| 16 | Metrics scrape | **Partial** | **A4** `MetricsExportGate` + **A5** stacked sim | Privileged raw scrape |
| 17 | Sphinx verify | **Partial** | KATs + S1 oracle + **ProVerif L1–L3** + **A6** fuzz | EasyCrypt / computational proof |
| 18 | Jurisdiction path (B2) | **Partial** | `[path] require_diverse_jurisdictions` | Charter legal External |
| 19 | Joint guard×gossip (B3) | **[O] QUANTIFIED** | `joint_guard_gossip` + `joint_v4_stacked` | Field rates; BFT External |

## Product knobs (quick)

| Knob | Prefer |
|------|--------|
| Guard mitigation | `preset = "adaptive_v4"` (default off) |
| Gossip | stacked defaults when `[health_gossip]` enabled |
| Cover multi-hop | `multihop_defense = "cover_onions"` (opt-in) |
| Exit | `presence_pad` when exit anonymity matters (opt-in) |
| Metrics | production `[metrics]` stacked gate |
| Path diversity | `require_diverse_jurisdictions` (opt-in soft filter) |

## Wave closure

**In-repo** coverage / verify / productize / leftovers waves are landed through tip `c7c2f0d`.  
Call-site profiling remains closed. Remaining blockers: **External** platform rows, formal computational proofs, operational C2, field rates, counsel-reviewed governance.  
**Do not** claim research closed. Historical plan: [`RESEARCH_UPGRADE_PLAN.md`](RESEARCH_UPGRADE_PLAN.md).
