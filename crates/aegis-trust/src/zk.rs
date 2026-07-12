//! ZK reputation proof interface (spec §4.8: "ZK reputation (scoped, non-PQ)").
//!
//! Two implementations of [`ZkReputationProof`] are provided:
//!
//! - [`BulletproofsReputationProof`] — **use this in production.** A genuine,
//!   transparent-setup Bulletproofs range proof (via the `bulletproofs` crate)
//!   that a relay's reputation score meets a public threshold without revealing
//!   the score. Reputation scores are `f64` values in `[0.0, 1.0]`; they are
//!   mapped to integers by multiplying by [`SCORE_SCALE`] (10_000) and rounding
//!   to the nearest integer, giving four decimal digits of precision. Proving
//!   `score >= threshold` reduces to proving `score_scaled - threshold_scaled`
//!   lies in `[0, 2^RANGE_BITS)` with `RANGE_BITS = 16` (Bulletproofs requires
//!   a power-of-two bit length; 16 bits comfortably covers deltas up to 10_000).
//!   Rounding can collapse distinct floats that differ by less than half a scale
//!   step (~5×10⁻⁵); callers should treat the threshold check as exact on scaled
//!   integers, approximate on raw `f64`.
//! - [`PlaintextReputationProof`] — reference / wiring-only implementation that
//!   embeds the plaintext score in the proof. **Not zero-knowledge.** Use only
//!   for integration tests of the surrounding trust pipeline.
//!
//! **Scope note:** these proofs establish threshold membership for a reputation
//! score; they do **not** hide the relay's *identity*. Unlinking a proof from
//! a specific relay is a separate anonymity property (out of scope here).

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;

use crate::reputation::ReputationScore;

/// Scale factor mapping `[0.0, 1.0]` reputation scores to integers.
pub const SCORE_SCALE: u64 = 10_000;

/// Bit-length for the Bulletproofs range proof on `score_scaled - threshold_scaled`.
pub const RANGE_BITS: usize = 16;

const TRANSCRIPT_LABEL: &[u8] = b"aegis-trust/reputation-range-proof/v1";

/// A proof that some relay's reputation satisfies `threshold` without (in a real
/// implementation) revealing the relay's identity or exact score.
///
/// # Warning
/// [`PlaintextReputationProof`] does NOT provide the privacy half of this contract
/// — see its own docs. Prefer [`BulletproofsReputationProof`] for any setting
/// where the score must stay hidden.
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

/// Map a reputation value in `[0.0, 1.0]` to a scaled `u64` integer.
pub fn scale_reputation(value: f64) -> u64 {
    let clamped = value.clamp(0.0, 1.0);
    (clamped * SCORE_SCALE as f64).round() as u64
}

fn append_threshold(transcript: &mut Transcript, threshold_scaled: u64) {
    transcript.append_message(b"threshold_scaled", &threshold_scaled.to_le_bytes());
}

fn shared_pc_gens() -> PedersenGens {
    PedersenGens::default()
}

fn shared_bp_gens() -> BulletproofGens {
    BulletproofGens::new(64, 1)
}

/// Genuine zero-knowledge range proof via Bulletproofs (transparent setup).
///
/// The [`BulletproofsProof`] payload holds only a Pedersen commitment to
/// `score_scaled - threshold_scaled` and the serialized range proof — never the
/// score or the raw scalar difference.
pub struct BulletproofsReputationProof;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulletproofsProof {
    /// Pedersen commitment to `(score_scaled - threshold_scaled)` at prove time.
    pub commitment: [u8; 32],
    /// Serialized [`RangeProof`] bytes.
    pub range_proof: Vec<u8>,
}

impl ZkReputationProof for BulletproofsReputationProof {
    type Proof = BulletproofsProof;

    fn prove(score: ReputationScore, threshold: f64) -> Self::Proof {
        let score_scaled = scale_reputation(score.0);
        let threshold_scaled = scale_reputation(threshold);

        if score_scaled < threshold_scaled {
            // Cannot honestly range-prove a negative delta; return a structurally
            // invalid proof that verification rejects (natural failure mode).
            return BulletproofsProof {
                commitment: [0u8; 32],
                range_proof: Vec::new(),
            };
        }

        let delta = score_scaled - threshold_scaled;
        let pc_gens = shared_pc_gens();
        let bp_gens = shared_bp_gens();
        let blinding = Scalar::random(&mut thread_rng());

        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        append_threshold(&mut transcript, threshold_scaled);

        let (range_proof, commitment) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            delta,
            &blinding,
            RANGE_BITS,
        )
        .expect("range proof generation should succeed for in-range delta");

        BulletproofsProof {
            commitment: commitment.to_bytes(),
            range_proof: range_proof.to_bytes(),
        }
    }

    fn verify(proof: &Self::Proof, threshold: f64) -> bool {
        let threshold_scaled = scale_reputation(threshold);

        let commitment = match CompressedRistretto::from_slice(&proof.commitment) {
            Ok(c) => c,
            Err(_) => return false,
        };

        let range_proof = match RangeProof::from_bytes(&proof.range_proof) {
            Ok(p) => p,
            Err(_) => return false,
        };

        let pc_gens = shared_pc_gens();
        let bp_gens = shared_bp_gens();

        let mut transcript = Transcript::new(TRANSCRIPT_LABEL);
        append_threshold(&mut transcript, threshold_scaled);

        range_proof
            .verify_single(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &commitment,
                RANGE_BITS,
            )
            .is_ok()
    }
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

    #[test]
    fn bulletproofs_proof_verifies_above_threshold() {
        let proof = BulletproofsReputationProof::prove(ReputationScore(0.8), 0.5);
        assert!(BulletproofsReputationProof::verify(&proof, 0.5));
    }

    #[test]
    fn bulletproofs_proof_fails_below_threshold() {
        // Below-threshold scores cannot be honestly proved; `prove` returns an
        // invalid proof blob and `verify` rejects it.
        let proof = BulletproofsReputationProof::prove(ReputationScore(0.2), 0.5);
        assert!(!BulletproofsReputationProof::verify(&proof, 0.5));
    }

    #[test]
    fn bulletproofs_truncated_commitment_rejects_without_panic() {
        // Invalid compressed Ristretto point (all zeros) — verify returns false, no panic.
        let proof = BulletproofsProof {
            commitment: [0u8; 32],
            range_proof: vec![0u8; 64],
        };
        assert!(!BulletproofsReputationProof::verify(&proof, 0.5));
    }

    #[test]
    fn bulletproofs_empty_range_proof_rejects_without_panic() {
        let proof = BulletproofsProof {
            commitment: [0u8; 32],
            range_proof: Vec::new(),
        };
        assert!(!BulletproofsReputationProof::verify(&proof, 0.5));
    }

    #[test]
    fn bulletproofs_garbage_range_proof_bytes_reject_without_panic() {
        let proof = BulletproofsProof {
            commitment: [0u8; 32],
            range_proof: vec![0xFF; 8],
        };
        assert!(!BulletproofsReputationProof::verify(&proof, 0.5));
    }

    #[test]
    fn bulletproofs_tampered_proof_fails() {
        let mut proof = BulletproofsReputationProof::prove(ReputationScore(0.8), 0.5);
        assert!(BulletproofsReputationProof::verify(&proof, 0.5));

        if !proof.range_proof.is_empty() {
            proof.range_proof[0] ^= 0xff;
        } else {
            panic!("expected non-empty range proof for valid score");
        }
        assert!(!BulletproofsReputationProof::verify(&proof, 0.5));
    }

    #[test]
    fn bulletproofs_tampered_commitment_fails() {
        let mut proof = BulletproofsReputationProof::prove(ReputationScore(0.8), 0.5);
        proof.commitment[0] ^= 0xff;
        assert!(!BulletproofsReputationProof::verify(&proof, 0.5));
    }

    #[test]
    fn bulletproofs_wrong_threshold_fails() {
        let proof = BulletproofsReputationProof::prove(ReputationScore(0.8), 0.5);
        assert!(!BulletproofsReputationProof::verify(&proof, 0.6));
    }

    #[test]
    fn bulletproofs_proof_carries_no_plaintext_score() {
        // Structural privacy check: `BulletproofsProof` has no score field, and
        // `verify` takes only `&BulletproofsProof` + public threshold.
        let proof = BulletproofsReputationProof::prove(ReputationScore(0.81234), 0.5);
        assert!(BulletproofsReputationProof::verify(&proof, 0.5));

        // The scaled score 8123 (0.8123) must not appear as LE bytes in the proof.
        let score_bytes = scale_reputation(0.81234).to_le_bytes();
        assert!(
            !proof.range_proof.windows(8).any(|w| w == score_bytes),
            "range proof must not embed the plaintext scaled score"
        );
        assert!(
            !proof.commitment.windows(8).any(|w| w == score_bytes),
            "commitment must not embed the plaintext scaled score"
        );
    }

    #[test]
    fn scale_reputation_rounds_to_four_decimal_places() {
        assert_eq!(scale_reputation(0.81234), 8_123);
        assert_eq!(scale_reputation(0.81236), 8_124);
        assert_eq!(scale_reputation(1.0), 10_000);
        assert_eq!(scale_reputation(0.0), 0);
    }
}
