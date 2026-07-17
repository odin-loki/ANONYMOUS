# AEGIS research / ops residual hardening plan

**Status:** complete (2026-07-17)  
**Scope:** Close every residual listed under *Profiling complete* in
`AEGIS_implementation_threat_model.md` that was deferred as research/ops.

## Definition of done

Each residual must have:

1. Working code (or ops tooling) under `crates/` / `sim/` / `docs/ops/`
2. Tests or a documented dry-run procedure
3. Threat-model row updated from “accepted residual” → Mitigated / Partial with
   an honest leftover note
4. Entry in the completion log at the bottom of this file

## Workstreams

| # | Residual | Approach | Status |
|---|----------|----------|--------|
| 1 | Real TEE attestation | `AttestationProvider` + software quotes; hardware plug-in docs | **Partial** |
| 2 | Consortium key ceremony | Ops runbook + `aegis-ceremony` | **Partial** |
| 3 | Noise / roster-key link auth | Optional Noise_IK-compatible (`noise-link`) | **Partial/Mitigated** |
| 4 | Unix / full keychain KEM store | `kem-keyring` + DPAPI | **Partial/Mitigated** |
| 5 | Cover-burst timing | τ-paced cover egress (default 0.35s) | **Partial** |
| 6 | Cross-relay health gossip | Signed `PeerHealthAdvert` | **Partial** |
| 7 | ZK anonymous reputation | Anonymous presentation + nullifier API | **Partial** |
| 8 | Adversarial multi-conn flood | Default global ingress budget 8/τ | **Mitigated** |
| 9 | Sybil / g=3 guard plateau | `GUARD_SET_SIZE=3` + production helpers + `test-utils` API fence | **Mitigated** |
| 10 | dudect / CT evidence | In-tree smoke + WSL dudect ops doc | **Partial** |
| 11 | Per-peer fair queues | Per-peer inbound + weighted WFQ-style drain | **Partial/Mitigated** |

## Ops documentation index

| Doc | Topic |
|-----|--------|
| [`docs/ops/tee_attestation.md`](ops/tee_attestation.md) | Software quotes + SGX/SEV plug-in |
| [`docs/ops/consortium_key_ceremony.md`](ops/consortium_key_ceremony.md) | M-of-N ceremony |
| [`docs/ops/noise_link_auth.md`](ops/noise_link_auth.md) | Noise_IK-compatible hop auth |
| [`docs/ops/health_gossip.md`](ops/health_gossip.md) | PeerHealthAdvert protocol |
| [`docs/ops/anonymous_reputation.md`](ops/anonymous_reputation.md) | Anonymous presentation vs full AC |
| [`docs/ops/constant_time_ci.md`](ops/constant_time_ci.md) | Timing smoke + WSL dudect |

## Non-goals / honesty bounds (still true)

- No claim of hardware TEE attestation without a real enclave SDK.
- Cover timing is empirical τ-alignment, not information-theoretic indistinguishability.
- Health gossip is not BFT reputation consensus.
- Anonymous reputation is not a paper-complete anonymous credential system.
- Noise path uses SHA3-256 (not BLAKE2s/`snow` byte-compatible Noise).

## Completion log

| # | Status | Notes |
|---|--------|-------|
| 1 | **Partial** | `AttestationProvider` + `SoftwareAttestationProvider`; `core_gates_hold_under_attested`; `docs/ops/tee_attestation.md` |
| 2 | **Partial** | `docs/ops/consortium_key_ceremony.md` + `aegis-ceremony` + optional GF(256) Shamir shares |
| 3 | **Partial/Mitigated** | `noise_link` + `LinkHandshakeMode::Noise`; default LegacyPsk |
| 4 | **Partial/Mitigated** | Unix `kem-keyring` + Windows DPAPI; `0600` fallback |
| 5 | **Partial** | `cover_cell_tau` paced cover dispatcher |
| 6 | **Partial** | `PeerHealthAdvert` + `majority_k` median merge + `docs/ops/health_gossip.md` |
| 7 | **Partial** | `AnonymousReputationPresentation` + nullifier helper |
| 8 | **Mitigated** | Default `global_max_cells_per_sec = 8/τ` |
| 9 | **Mitigated** | `GUARD_SET_SIZE=3` + `build_bound_path_pruned_with_guards`; unfiltered APIs gated `test-utils` |
| 10 | **Partial** | `dudect_smoke` + `docs/ops/constant_time_ci.md` |
| 11 | **Partial/Mitigated** | Per-peer inbound queues + RR fair drain |

## Verification

```text
cd crates && cargo test --workspace
```

All packages green at closeout (2026-07-17).
