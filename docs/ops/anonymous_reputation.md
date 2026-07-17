# Anonymous reputation presentation (ops / research)

**Status (2026-07-17): Partial** — threshold ZK + local nullifier registry shipped; full anonymous credentials / issuer deferred.

## What shipped

| Piece | API / location | Notes |
|-------|----------------|-------|
| Bulletproofs threshold proof | `aegis_trust::BulletproofsReputationProof` | Proves `score >= threshold` without revealing the score |
| Anonymous presentation | `AnonymousReputationPresentation { proof, score_commitment }` via `present_anonymous` / `verify_anonymous` | **No `RelayId` in serialized proof bytes** |
| Out-of-band nullifier | `derive_reputation_nullifier(relay_id, epoch, blinding)` | Verifier binds identity / spend-once **outside** the proof blob |
| Local nullifier registry | `aegis_trust::NullifierRegistry` + `verify_anonymous_and_spend` | File-backed spent set **per epoch**; rejects replay on this node |
| Node optional path | `[reputation] nullifier_registry_path` in `aegis-node` TOML | Load on start; save on health drain + shutdown |

`score_commitment` is the Pedersen commitment to `(score_scaled - threshold_scaled)` (same bytes as `proof.commitment`), exposed so a policy layer can bind the presentation to a ledger entry or nullifier without putting a cleartext relay id into the ZK payload.

### Verifier checklist (current)

1. `verify_anonymous(presentation, threshold)` — cryptographic threshold check.
2. Register / reject via `NullifierRegistry::try_register` (or `verify_anonymous_and_spend`) per epoch policy.
3. Persist registry when `nullifier_registry_path` is set (local only).
4. Do **not** expect RelayId inside `proof.range_proof` / commitments.

### Node TOML example

```toml
[reputation]
ledger_path = "data/reputation.json"
nullifier_registry_path = "data/nullifiers.json"
```

## Honesty bounds — not a full AC issuer

This slice is **not** a paper-complete anonymous credential system. Still deferred:

1. **Anonymous credentials / unlinkable showings** across epochs without a shared blinding channel.
2. **Consensus-backed score commitments** (multi-operator ledger) so the Pedersen opening is globally agreed.
3. **Cross-node nullifier consensus** — today's registry is local/file-backed; another node does not see spends.
4. **PQ-safe** reputation proofs (spec scopes current ZK as non-PQ).
5. **Wire format + gossip** for presentations between relays/clients.
6. **Issuer / accumulator** so a relay cannot forge a threshold proof for a score it does not hold in a shared ledger.

## Threat model

See `docs/AEGIS_implementation_threat_model.md` and `docs/ops/RESEARCH_OPS_STATUS.md` — ZK anonymous reputation row is **Partial**: score threshold is ZK; local replay prevention is Done; identity unlinkability / issuer / multi-node spend are External/deferred.
