//! ZK reputation proof interface (spec §4.8: "ZK reputation (scoped, non-PQ)").
//!
//! Genuine zero-knowledge proof construction (a real circuit — e.g. proving
//! "my reputation score exceeds threshold T" without revealing the score or
//! relay identity, likely Groth16/Plonk-style per the spec's own aside that
//! "BLS/Groth16 elsewhere are not [post-quantum], and must never protect traffic
//! content") is out of scope for this pass — it requires a proving-system
//! dependency, a circuit definition, and a trusted-setup or transparent-setup
//! decision that deserves its own dedicated phase, not a rushed add-on here.
//!
//! What's provided: the [`ZkReputationProof`] trait as the integration point a
//! real circuit-backed prover/verifier would implement, plus
//! [`PlaintextReputationProof`] — a working reference implementation that
//! satisfies the trait's functional contract (prove-then-verify round-trips
//! correctly) but is explicitly, loudly NOT zero-knowledge: it reveals the exact
//! score. Use it only for wiring/testing the surrounding system, never as a
//! privacy control.

use crate::reputation::ReputationScore;

/// A proof that some relay's reputation satisfies `threshold` without (in a real
/// implementation) revealing the relay's identity or exact score.
///
/// # Warning
/// [`PlaintextReputationProof`] is the only implementation shipped here and does
/// NOT provide the privacy half of this contract — see its own docs.
pub trait ZkReputationProof {
    type Proof;

    /// Produce a proof that `score >= threshold`.
    fn prove(score: ReputationScore, threshold: f64) -> Self::Proof;

    /// Verify a proof against the PUBLIC `threshold` (the score itself must not
    /// need to be supplied here in a real ZK implementation — `PlaintextReputationProof`
    /// violates this by embedding the score in the proof; a real implementation
    /// would not take `score` as a verifier input at all).
    fn verify(proof: &Self::Proof, threshold: f64) -> bool;
}

/// NON-PRIVATE reference implementation: the "proof" is literally the plaintext
/// score. Round-trips correctly (useful for integration testing the rest of the
/// trust pipeline) but provides ZERO confidentiality. Do not use where the score
/// or relay identity must stay hidden — that requires the real ZK circuit this
/// module defers (see module docs).
pub struct PlaintextReputationProof;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlaintextProof {
    pub revealed_score: f64,
}

impl ZkReputationProof for PlaintextReputationProof {
    type Proof = PlaintextProof;

    fn prove(score: ReputationScore, _threshold: f64) -> Self::Proof {
        PlaintextProof {
            revealed_score: score.0,
        }
    }

    fn verify(proof: &Self::Proof, threshold: f64) -> bool {
        proof.revealed_score >= threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_proof_round_trips_above_threshold() {
        let proof = PlaintextReputationProof::prove(ReputationScore(0.8), 0.5);
        assert!(PlaintextReputationProof::verify(&proof, 0.5));
    }

    #[test]
    fn plaintext_proof_round_trips_below_threshold() {
        let proof = PlaintextReputationProof::prove(ReputationScore(0.2), 0.5);
        assert!(!PlaintextReputationProof::verify(&proof, 0.5));
    }
}
