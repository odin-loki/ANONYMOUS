# Research / ops residual status (one-page)

**Date:** 2026-07-17  
**Wave:** research/ops leftovers after **Profiling complete**  
**Plan:** [`docs/AEGIS_research_ops_hardening_plan.md`](../AEGIS_research_ops_hardening_plan.md)

Legend: **Done** = in-tree code + tests/docs as scoped · **Partial** = useful mitigation with honest leftover · **External** = B-class (hardware SDK, multi-org BFT, full dudect lab, etc.) — not unfinished wiring.

| # | Residual | Status | In-tree | Leftover / External |
|---|----------|--------|---------|---------------------|
| 1 | Real TEE attestation | **Partial** | `AttestationProvider` + software quotes; `docs/ops/tee_attestation.md` | **External:** hardware TEE SDK (SGX/SEV) |
| 2 | Consortium key ceremony | **Partial** | `docs/ops/consortium_key_ceremony.md` + `aegis-ceremony` | **External:** HSM / Shamir MPC |
| 3 | Noise / roster-key link auth | **Partial** | Optional Noise_IK-compatible (`noise-link`) | BLAKE2s/`snow` byte-compat; default still LegacyPsk |
| 4 | Unix / keychain KEM store | **Partial** | Unix `kem-keyring` + Windows DPAPI | Same-user backends; `0600` fallback |
| 5 | Cover-burst timing | **Partial** | τ-paced cover egress | Not info-theoretic indistinguishability |
| 6 | Cross-relay health gossip | **Partial** | Signed `PeerHealthAdvert` | **External:** multi-org BFT reputation consensus |
| 7 | ZK anonymous reputation | **Partial** | Presentation + `NullifierRegistry` (local) | **External:** full AC issuer / consensus nullifiers |
| 8 | Adversarial multi-conn flood | **Done** | Default global ingress budget 8/τ | Tunable caps only |
| 9 | Sybil / g=3 guard plateau | **Done** | `GUARD_SET_SIZE=3` + production helpers | Unfiltered APIs remain (science) |
| 10 | dudect / CT evidence | **Partial** | In-tree smoke + ops doc | **External:** full WSL dudect lab proofs |
| 11 | Per-peer fair queues | **Partial/Mitigated** | Per-peer inbound + weighted credit RR (health success rate) | Outbound still shared; not continuous GPS |

## Wave closure

Research/ops leftovers wave is **closed** except B-class **External** items above (hardware TEE SDK, multi-org BFT, full dudect lab, full AC issuer). See README **Profiling complete** and the plan completion log.
