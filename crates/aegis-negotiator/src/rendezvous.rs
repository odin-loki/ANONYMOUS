//! Rotating rendezvous identifiers (spec §5.4).
//!
//! Endpoints derive a fresh rendezvous id per epoch from their pairwise shared secret.
//! **Must be computed end-to-end by the two peers only** — relays and the batch
//! scheduler never see the shared secret or long-term identities.

use sha3::{Digest, Sha3_256};

const DOMAIN: &[u8] = b"aegis/rendezvous/v1";

/// Deterministic, epoch-scoped rendezvous identifier from a pairwise shared secret.
///
/// Both endpoints independently compute the same id for `(secret, epoch)` without
/// further communication. Different epochs yield unrelated-looking ids.
#[must_use]
pub fn rendezvous_id(shared_secret: &[u8], epoch: u64) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN);
    h.update(shared_secret);
    h.update(&epoch.to_le_bytes());
    h.finalize().into()
}

/// Hamming distance between two equal-length byte strings (for epoch-unlinkability tests).
#[must_use]
pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendezvous_id_stable_per_epoch() {
        let secret = b"pairwise-shared-secret";
        let id0a = rendezvous_id(secret, 0);
        let id0b = rendezvous_id(secret, 0);
        assert_eq!(id0a, id0b);
    }

    #[test]
    fn rendezvous_id_differs_across_epochs() {
        let secret = b"pairwise-shared-secret";
        let id0 = rendezvous_id(secret, 0);
        let id1 = rendezvous_id(secret, 1);
        let id2 = rendezvous_id(secret, 2);
        assert_ne!(id0, id1);
        assert_ne!(id1, id2);
        assert_ne!(id0, id2);
    }

    #[test]
    fn rendezvous_id_differs_for_different_secrets() {
        assert_ne!(
            rendezvous_id(b"secret-a", 7),
            rendezvous_id(b"secret-b", 7)
        );
    }

    #[test]
    fn consecutive_epochs_high_hamming_distance() {
        let secret = b"test-secret-for-hamming";
        let mut distances = Vec::new();
        for epoch in 0..64 {
            let a = rendezvous_id(secret, epoch);
            let b = rendezvous_id(secret, epoch + 1);
            distances.push(hamming_distance(&a, &b));
        }
        let mean = distances.iter().sum::<u32>() as f64 / distances.len() as f64;
        // 256-bit digest: random independent strings expect ~128 bit differences.
        assert!(
            (100.0..=156.0).contains(&mean),
            "mean hamming distance {mean} not near 128"
        );
    }
}
