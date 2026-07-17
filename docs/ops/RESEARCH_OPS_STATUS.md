# Research / ops residual status (one-page)

**Date:** 2026-07-17  
**Wave:** research/ops leftovers after **Profiling complete**  
**Plan:** [`docs/AEGIS_research_ops_hardening_plan.md`](../AEGIS_research_ops_hardening_plan.md)

Legend: **Done** = in-tree code + tests/docs as scoped · **Partial** = useful mitigation with honest leftover · **External** = B-class (hardware SDK, multi-org BFT, full dudect lab, etc.) — not unfinished wiring.

| # | Residual | Status | In-tree | Leftover / External |
|---|----------|--------|---------|---------------------|
| 1 | Real TEE attestation | **Partial** | `AttestationProvider` + software quotes; `docs/ops/tee_attestation.md` | **External:** hardware TEE SDK (SGX/SEV) |
| 2 | Consortium key ceremony | **Partial** | `aegis-ceremony` + GF(256) Shamir seed shares | **External:** HSM / interactive MPC |
| 3 | Noise / roster-key link auth | **Partial** | `handshake=auto` → Noise when static keys present | BLAKE2s/`snow` byte-compat |
| 4 | Unix / keychain KEM store | **Partial** | Unix `kem-keyring` + Windows DPAPI | Same-user backends; `0600` fallback |
| 5 | Cover-burst timing | **Partial** | τ-paced cover egress | Not info-theoretic indistinguishability |
| 6 | Cross-relay health gossip | **Partial** | `PeerHealthAdvert` + majority_k median merge | **External:** multi-org BFT |
| 7 | ZK anonymous reputation | **Partial** | Presentation + file `NullifierRegistry` | **External:** full AC issuer |
| 8 | Adversarial multi-conn flood | **Done** | Global ingress budget 8/τ | Tunable caps only |
| 9 | Sybil / g=3 guard plateau | **Done** | g=3 helpers; unfiltered APIs `test-utils` only | Science tests keep unfiltered |
| 10 | dudect / CT evidence | **Partial** | In-tree smoke + ops doc | **External:** full WSL dudect lab |
| 11 | Per-peer fair queues | **Partial/Mitigated** | Health-weighted inbound WFQ | Outbound still shared |
| 12 | Emitter backlog | **Done** | Cap 256; fail send on full | — |

## Wave closure

**In-repo profiling is DONE.** Remaining items are B-class **External** only
(hardware TEE SDK, HSM/MPC, multi-org BFT, full AC issuer, full dudect lab,
BLAKE2s-Noise byte-compat). See README and the plan completion log.
