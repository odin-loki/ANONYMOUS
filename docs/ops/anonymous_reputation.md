# Anonymous reputation presentation (ops / research)

**Status (2026-07-17): Partial** — threshold ZK + local nullifier registry + minimal software issuer shipped; full interactive AC / real ZK show still **External**.

## What shipped

| Piece | API / location | Notes |
|-------|----------------|-------|
| Bulletproofs threshold proof | `aegis_trust::BulletproofsReputationProof` | Proves `score >= threshold` without revealing the score |
| Anonymous presentation | `AnonymousReputationPresentation { proof, score_commitment }` via `present_anonymous` / `verify_anonymous` | **No `RelayId` in serialized proof bytes** |
| Out-of-band nullifier | `derive_reputation_nullifier(relay_id, epoch, blinding)` | Verifier binds identity / spend-once **outside** the proof blob |
| Local nullifier registry | `aegis_trust::NullifierRegistry` + `verify_anonymous_and_spend` | File-backed spent set **per epoch**; rejects replay on this node |
| Shared nullifier sync (Partial) | `NullifierRegistry::export_to_file` / `merge_from_file` | Operator file exchange merges peer spends idempotently; rejects corrupt duplicate entries; **not** cross-node consensus |
| Minimal issuer (Partial) | `AnonymousCredentialIssuer` / `IssuedAnonymousCredential` | Software-bound Ed25519 token: epoch + score band + presentation + nullifier; `AnonymousCredentialIssuerParams::save_to_file` for verifier pubkey |
| Blinded issuance (Partial) | `BlindedIssueRequest` / `BlindedIssueResponse` + `issue_from_blinded_request` | Client sends ZK presentation + nullifier (no RelayId in JSON); issuer verifies threshold without exact score; **not** interactive AC / blind signatures |
| Epoch rotation (Partial) | `AnonymousCredentialIssuer::rotate_epoch` → `NullifierRegistry::forget_epoch` | Operator GC of spent nullifiers when rolling credential epoch |
| Node optional path | `[reputation] nullifier_registry_path` in `aegis-node` TOML | Load on start; save on health drain + shutdown |

`score_commitment` is the Pedersen commitment to `(score_scaled - threshold_scaled)` (same bytes as `proof.commitment`), exposed so a policy layer can bind the presentation to a ledger entry or nullifier without putting a cleartext relay id into the ZK payload.

### Verifier checklist (current)

1. Load issuer pubkey via `AnonymousCredentialIssuerParams::load_from_file` (or embed in policy).
2. `AnonymousCredentialIssuer::verify_credential` or `verify_and_spend` — issuer signature + `verify_anonymous`.
3. Register / reject via `NullifierRegistry::try_register` (or `verify_anonymous_and_spend`) per epoch policy.
4. Persist registry when `nullifier_registry_path` is set (local only).
5. To share spends across co-located nodes without gossip: export from node A (`export_to_file`), merge on node B (`merge_from_file` or `ReputationConfig::merge_nullifier_registry_from`), then save. Re-import is idempotent; corrupt files with duplicate nullifiers in one epoch are rejected.
6. Do **not** expect RelayId inside `proof.range_proof` / commitments.

### Issuer flow (Partial)

```rust
let issuer = AnonymousCredentialIssuer::from_seed(seed);
issuer.public_params().save_to_file("data/issuer_params.json")?;

let cred = issuer.issue(score, band_floor, &relay_id, epoch, &blinding)?;
// Or blinded path (no relay_id on wire to issuer):
let req = AnonymousCredentialIssuer::build_blinded_request(score, band_floor, &relay_id, epoch, &blinding)?;
let resp = issuer.issue_from_blinded_request(&req)?;
// Verifier:
AnonymousCredentialIssuer::verify_and_spend(&params, &mut registry, &resp.credential)?;
// Epoch rollover:
AnonymousCredentialIssuer::rotate_epoch(&mut registry, old_epoch);
```

The issuer **sees `relay_id` at issue time**; the spent credential exposes only the anonymous presentation + nullifier. This is honest software binding, not unlinkable multi-show AC.

### Node TOML example

```toml
[reputation]
ledger_path = "data/reputation.json"
nullifier_registry_path = "data/nullifiers.json"
```

## Honesty bounds — not a full AC issuer

This slice is **not** a paper-complete anonymous credential system. Still **External**:

1. **Interactive blinded issuance** — no ZK show protocol; issuer learns `relay_id` when signing.
2. **Anonymous credentials / unlinkable showings** across epochs without a shared blinding channel.
3. **Consensus-backed score commitments** (multi-operator ledger) so the Pedersen opening is globally agreed.
4. **Cross-node nullifier consensus** — file merge shares spends operator-to-operator; no wire gossip or BFT ledger.
5. **PQ-safe** reputation proofs (spec scopes current ZK as non-PQ).
6. **Wire format + gossip** for presentations between relays/clients.
7. **Accumulator / consensus issuer** so a relay cannot forge a threshold proof for a score it does not hold in a shared ledger.

## Threat model

See `docs/AEGIS_implementation_threat_model.md` and `docs/ops/RESEARCH_OPS_STATUS.md` — ZK anonymous reputation row is **Partial**: score threshold is ZK; local replay prevention is Done; identity unlinkability / issuer / multi-node spend are External/deferred.

## Gossip / reputation anonymity (eclipse, `majority_k`)

Cross-relay health gossip can demote relays via median failure rates once `majority_k`
distinct authority reporters agree ([`health_gossip.md`](health_gossip.md)). This is
**not** multi-org BFT and does **not** close gossip-eclipse risks.

| Risk | Status | Mitigation / residual |
|------|--------|------------------------|
| **Eclipse** — victim sees only adversarial neighbors | **Partial** | Peer table is config-bound; no global gossip view. All-neighbor collusion ⇒ biased medians only. See [`ATTACK_PLAYBOOK.md`](ATTACK_PLAYBOOK.md) §10. |
| **`majority_k` collusion** | **Partial** | Default `majority_k = 2`; K colluding admitted reporters can shift median at half weight. Lab may set `majority_k = 1` — not for production. |
| Nullifier merge eclipse | **Partial** | File export/merge is operator-authenticated out-of-band; no wire consensus. |
| Issuer learns identity at issue | **Open by design (Partial AC)** | Blinded request still binds at issue; not unlinkable multi-show AC. |

**Operator guidance:** diversify gossip neighbors; keep `majority_k ≥ 2`; do not treat
gossip median as sole ground truth; pair with independent health checks and charter
dispute process ([`CONSORTIUM_CHARTER.md`](CONSORTIUM_CHARTER.md)).

## Lab characterization (wave C4) — [O] QUANTIFIED

In-repo lab (no Docker): `sim/aegis_sim/ac_nullifier_unlinkability.py` + committed
artifact `sim/data/ac_nullifier_unlinkability.json` + CI
`sim/tests/test_ac_nullifier_unlinkability.py`.

| Residual | Lab score (artifact) | Meaning |
|----------|----------------------|---------|
| Issuer correlation at `issue` | **1.0** | Issuer learns `relay_id` |
| Issuer nullifier→spend link (blinded) | **1.0** | Request omits RelayId; nullifier still links issue session to spend |
| Local double-spend | **0.0** | `try_register` rejects replay on one node |
| Partition double-accept pre-merge | **1.0** | Two registries both accept before merge |
| Delayed merge window | **~0.375** | Mean exposure ≈ delay/window on default grid |
| Merge-path eclipse (export suppressed) | **1.0** | Victim never imports peer spends |
| Verifier presentation RelayId leak | **0.0** | Proof/presentation JSON has no RelayId |

**Composite residual (weighted lab):** see artifact `composite_residual_risk` (~0.86).

This **characterizes** Partial AC + file-merge residuals. It does **not** claim
interactive ZK issuance, paper-complete unlinkable multi-show AC, or cross-node
nullifier consensus.
