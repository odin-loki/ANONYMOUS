# Research / ops residual status (one-page)

**Date:** 2026-07-18  
**Wave:** Do-all External advance (TEE/HSM contracts, BFT checkpoint, blinded AC, dudect lab, CI/ops)  
**Plan:** [`docs/AEGIS_research_ops_hardening_plan.md`](../AEGIS_research_ops_hardening_plan.md)

Legend: **Done** = in-tree code + tests/docs as scoped · **Partial** = useful mitigation with honest leftover · **External** = B-class (hardware SDK, multi-org BFT, full dudect lab, etc.) — not unfinished wiring.

| # | Residual | Status | In-tree | Leftover / External |
|---|----------|--------|---------|---------------------|
| 1 | Real TEE attestation | **Partial** | Software quotes + `HardwareTeeProvider` fail-closed; DCAP/SEV request types; `ATQ1` envelope parse (layout only); `tee-hardware` hook; `docs/ops/tee_attestation.md` | **External:** link Intel DCAP / AMD SEV-SNP SDK + platform device |
| 2 | Consortium key ceremony | **Partial** | Shamir + `Pkcs11CustodyOps`; HSM fail-closed + lab `SimulatedHsmProvider`; `docs/ops/consortium_key_ceremony.md` | **External:** PKCS#11 / vendor HSM SDK + interactive MPC |
| 3 | Noise / roster-key link auth | **Partial/Mitigated** | `handshake=auto` → `snow` Noise_IK when static keys present | Pre-snow SHA3 peers; ingress static |
| 4 | Unix / keychain KEM store | **Partial** | Unix `kem-keyring` + Windows DPAPI; refuse group/world-readable `kem.seeds` | **External:** HSM / cross-user secret store |
| 5 | Cover-burst timing | **Partial** | τ-paced cover egress | Not info-theoretic indistinguishability |
| 6 | Cross-relay health gossip | **Partial** | Authority-set quorum log + `majority_k` + optional `HealthEpochCheckpoint`; `docs/ops/health_gossip.md` | **External:** multi-org BFT |
| 7 | ZK anonymous reputation | **Partial** | Issuer + blinded issue types + epoch rotate + nullifier merge; `docs/ops/anonymous_reputation.md` | **External:** interactive AC / real ZK show |
| 8 | Adversarial multi-conn flood | **Done** | Global ingress budget 8/τ | Tunable caps only |
| 9 | Sybil / g=3 guard plateau | **Done** | g=3 helpers; unfiltered APIs `test-utils` only | Science tests keep unfiltered |
| 10 | dudect / CT evidence | **Partial** | Smokes + `tools/dudect/` lab Makefile + WSL scripts → `sim/dudect_lab_attempt.txt` + CI sim-pytest | **External:** ≥10⁵ traces/primitive on isolated CPU |
| 11 | Per-peer fair queues | **Done** | Health-weighted inbound + outbound WFQ | Discrete weight quanta (not GPS) |
| 12 | Emitter backlog | **Done** | Cap 256; fail send on full | — |

## Wave closure

**In-repo work for all listed residuals is advanced as far as software allows.**
Call-site profiling remains closed. Remaining blockers are operator/platform
**External** only (TEE SDK, PKCS#11/HSM, multi-org BFT, interactive AC/real ZK,
isolated dudect ≥10⁵). See also `docs/ops/DEPLOYMENT.md`.

**Research backlog (honest §13 + External map):** [`RESEARCH_AGENDA.md`](RESEARCH_AGENDA.md)
— scaffolding done, integration + science [O] items **not** claimed closed.
