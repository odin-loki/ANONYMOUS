# Anonymous reputation presentation (ops / research)

**Status (2026-07-17): Partial** — threshold ZK shipped; full anonymous credentials deferred.

## What shipped

| Piece | API / location | Notes |
|-------|----------------|-------|
| Bulletproofs threshold proof | `aegis_trust::BulletproofsReputationProof` | Proves `score >= threshold` without revealing the score |
| Anonymous presentation | `AnonymousReputationPresentation { proof, score_commitment }` via `present_anonymous` / `verify_anonymous` | **No `RelayId` in serialized proof bytes** |
| Out-of-band nullifier | `derive_reputation_nullifier(relay_id, epoch, blinding)` | Verifier binds identity / spend-once **outside** the proof blob |

`score_commitment` is the Pedersen commitment to `(score_scaled - threshold_scaled)` (same bytes as `proof.commitment`), exposed so a policy layer can bind the presentation to a ledger entry or nullifier without putting a cleartext relay id into the ZK payload.

### Verifier checklist (current)

1. `verify_anonymous(presentation, threshold)` — cryptographic threshold check.
2. Out-of-band: accept/reject `ReputationNullifier` (or a known ledger commitment) per epoch policy.
3. Do **not** expect RelayId inside `proof.range_proof` / commitments.

## Acceptance criteria — future work (full AC)

Not shipped in this slice:

1. **Anonymous credentials / unlinkable showings** across epochs without a shared blinding channel.
2. **Consensus-backed score commitments** (multi-operator ledger) so the Pedersen opening is globally agreed.
3. **PQ-safe** reputation proofs (spec scopes current ZK as non-PQ).
4. **Wire format + gossip** for presentations between relays/clients.
5. **Issuer / accumulator** so a relay cannot forge a threshold proof for a score it does not hold in the shared ledger.
6. **Nullifier registry** with cross-node double-spend detection (today: local/policy only).

## Threat model

See `docs/AEGIS_implementation_threat_model.md` — ZK anonymous reputation row is **Partial**: score threshold is ZK; identity unlinkability depends on nullifier/blinding discipline and is not a full anonymous-credential system.
