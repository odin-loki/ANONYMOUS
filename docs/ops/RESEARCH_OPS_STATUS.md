# Research / ops residual status (one-page)

**Date:** 2026-07-17  
**Wave:** External-boundary closeout (HSM custody stub, KEM mode refuse, nullifier merge)  
**Plan:** [`docs/AEGIS_research_ops_hardening_plan.md`](../AEGIS_research_ops_hardening_plan.md)

Legend: **Done** = in-tree code + tests/docs as scoped · **Partial** = useful mitigation with honest leftover · **External** = B-class (hardware SDK, multi-org BFT, full dudect lab, etc.) — not unfinished wiring.

| # | Residual | Status | In-tree | Leftover / External |
|---|----------|--------|---------|---------------------|
| 1 | Real TEE attestation | **Partial** | `AttestationProvider` + software quotes; `HardwareTeeProvider` fail-closed stub + `HardwareQuoteFields`; `select_attestation_provider`; `docs/ops/tee_attestation.md` | **External:** link Intel DCAP / AMD SEV-SNP SDK + platform device for real quotes |
| 2 | Consortium key ceremony | **Partial** | `aegis-ceremony` + GF(256) Shamir; `SoftwareCustodyProvider` / `HsmCustodyProvider` fail-closed stub + `select_ceremony_custody`; `docs/ops/consortium_key_ceremony.md` | **External:** link PKCS#11 / vendor HSM SDK + interactive MPC ceremony |
| 3 | Noise / roster-key link auth | **Partial/Mitigated** | `handshake=auto` → `snow` Noise_IK when static keys present | Pre-snow SHA3 peers; ingress static |
| 4 | Unix / keychain KEM store | **Partial** | Unix `kem-keyring` + Windows DPAPI same-user; load refuses group/world-readable `kem.seeds` on Unix (`assert_kem_seed_file_mode_safe`); write `0600` fallback when keychain absent | **External:** HSM / cross-user secret store |
| 5 | Cover-burst timing | **Partial** | τ-paced cover egress | Not info-theoretic indistinguishability |
| 6 | Cross-relay health gossip | **Partial** | `PeerHealthAdvert` + BFT-lite quorum append log + `majority_k` median merge; `docs/ops/health_gossip.md` | **External:** multi-org BFT |
| 7 | ZK anonymous reputation | **Partial** | Presentation + `NullifierRegistry` + `AnonymousCredentialIssuer` + file merge (`merge_from_file` / `export_to_file`) for operator shared spends | **External:** interactive AC / real ZK show |
| 8 | Adversarial multi-conn flood | **Done** | Global ingress budget 8/τ | Tunable caps only |
| 9 | Sybil / g=3 guard plateau | **Done** | g=3 helpers; unfiltered APIs `test-utils` only | Science tests keep unfiltered |
| 10 | dudect / CT evidence | **Partial** | Smokes + `tools/dudect/` C skeleton + `aegis-crypto-dudect-ffi` (`aegis_ct_*`) + ops doc | **External:** operator-run oreparaz/dudect on isolated CPU lab (≥10⁵ traces; WSL2 insufficient) |
| 11 | Per-peer fair queues | **Done** | Health-weighted inbound + outbound WFQ | Discrete weight quanta (not GPS) |
| 12 | Emitter backlog | **Done** | Cap 256; fail send on full | — |

## Wave closure

**In-repo profiling and External-boundary scaffolding are DONE.**
No closable call-site or Partial-scaffold A/C items remain.
Remaining work is operator/platform **External** only (link TEE SDK, HSM/MPC,
multi-org BFT, interactive AC/real ZK, oreparaz/dudect on isolated CPU).
Pre-`snow` SHA3 Noise peers require `noise-link-legacy-sha3` migration only.
