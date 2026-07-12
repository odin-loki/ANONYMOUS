//! Public randomness beacon for cover scheduling + committee assignment (spec §4.7).
//!
//! The spec calls for a "threshold-BLS drand-style" beacon. Real threshold-BLS
//! (distributed key generation, per-round partial signatures, and threshold
//! aggregation across an independent quorum of beacon nodes) is a substantial
//! cryptographic subsystem in its own right and is **out of scope for this pass**
//! — implementing it shallowly would be exactly the kind of "half-implemented
//! crypto" this project's governing principle warns against (see crate-level docs
//! elsewhere in this workspace). What IS implemented here is the **interface and
//! consumption side** the rest of the system needs (a per-round public randomness
//! value used for cover-traffic scheduling and committee assignment), backed by a
//! [`HashChainBeacon`] reference implementation that is real, deterministic, and
//! independently verifiable by any party who holds the per-epoch seed — but it is
//! **single-authority**, not threshold-distributed. It provides *verifiability*
//! (anyone can recompute round `r`'s value from the seed) but NOT the
//! *unpredictability-until-published* / *liveness-under-partial-compromise*
//! properties a genuine threshold-BLS beacon gives you. Swap in a real
//! `drand`-style client behind the [`Beacon`] trait when that subsystem exists;
//! do not mistake [`HashChainBeacon`] for a production randomness source.
//!
//! Explicitly OUT of scope, per spec §4.7: the beacon does **not** drive topology
//! churn (churn accelerates intersection, §4.5/§12) and does **not** drive path
//! determinism (path selection stays fresh-CSPRNG-random per [`crate::path`]).
//! Its only jobs here are cover-schedule timing and committee assignment.

use sha3::{Digest, Sha3_256};

use crate::types::RelayId;

/// A source of per-round public randomness.
pub trait Beacon {
    /// 32 bytes of public randomness for `round`. Must be deterministic for a
    /// given `(beacon instance, round)` so all parties agree without communicating.
    fn randomness(&self, round: u64) -> [u8; 32];
}

/// Reference beacon: `value(r) = SHA3-256(domain || seed || r)`.
///
/// Verifiable by anyone holding `seed` (e.g. published once per epoch by the
/// consortium admission process — signing/distribution of `seed` itself is
/// future work, same as `RelayRoster`'s deferred persistence/signing).
/// NOT threshold-distributed — see module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HashChainBeacon {
    seed: [u8; 32],
}

impl HashChainBeacon {
    pub fn new(seed: [u8; 32]) -> Self {
        Self { seed }
    }
}

impl Beacon for HashChainBeacon {
    fn randomness(&self, round: u64) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"aegis-beacon-v1");
        h.update(&self.seed);
        h.update(&round.to_le_bytes());
        h.finalize().into()
    }
}

/// Which beacon-timed round wall-clock `time_s` falls into, given `round_period_s`.
pub fn round_at(time_s: f64, round_period_s: f64) -> u64 {
    (time_s / round_period_s).floor().max(0.0) as u64
}

/// Assign a fixed-size cover-scheduling committee for `round` from `pool` using
/// beacon randomness (Fisher–Yates prefix over a seeded shuffle, no OS RNG — every
/// party with the beacon value gets the SAME committee, which is the point: this
/// is for coordinating which relays generate cover traffic this round, not for
/// per-packet path selection, which must stay independently CSPRNG-random).
pub fn committee_for_round<B: Beacon>(
    beacon: &B,
    pool: &[RelayId],
    round: u64,
    committee_size: usize,
) -> Vec<RelayId> {
    if pool.is_empty() || committee_size == 0 {
        return Vec::new();
    }
    let mut candidates = pool.to_vec();
    let randomness = beacon.randomness(round);
    let n = candidates.len();
    let take = committee_size.min(n);

    for i in 0..take {
        // Deterministic pseudo-random index derived from beacon randomness + i,
        // re-hashed so a single 32-byte draw can seed many swaps.
        let mut h = Sha3_256::new();
        h.update(&randomness);
        h.update(&(i as u64).to_le_bytes());
        let digest = h.finalize();
        let raw = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
        let j = i + (raw as usize % (n - i));
        candidates.swap(i, j);
    }
    candidates.truncate(take);
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::RelayId;

    fn pool(n: u64) -> Vec<RelayId> {
        (1..=n).map(RelayId::from_u64).collect()
    }

    #[test]
    fn randomness_is_deterministic_per_round() {
        let b = HashChainBeacon::new([1u8; 32]);
        assert_eq!(b.randomness(10), b.randomness(10));
    }

    #[test]
    fn randomness_differs_across_rounds() {
        let b = HashChainBeacon::new([1u8; 32]);
        assert_ne!(b.randomness(10), b.randomness(11));
    }

    #[test]
    fn randomness_differs_across_seeds() {
        let a = HashChainBeacon::new([1u8; 32]);
        let b = HashChainBeacon::new([2u8; 32]);
        assert_ne!(a.randomness(10), b.randomness(10));
    }

    #[test]
    fn round_at_computes_floor_division() {
        assert_eq!(round_at(0.0, 10.0), 0);
        assert_eq!(round_at(9.999, 10.0), 0);
        assert_eq!(round_at(10.0, 10.0), 1);
        assert_eq!(round_at(25.0, 10.0), 2);
        assert_eq!(round_at(-5.0, 10.0), 0, "clamp negative time to round 0");
    }

    #[test]
    fn committee_is_deterministic_and_correct_size() {
        let b = HashChainBeacon::new([7u8; 32]);
        let relays = pool(20);
        let c1 = committee_for_round(&b, &relays, 5, 6);
        let c2 = committee_for_round(&b, &relays, 5, 6);
        assert_eq!(c1, c2, "same (beacon, round) must give same committee");
        assert_eq!(c1.len(), 6);
        // all members drawn from pool, no duplicates
        let unique: std::collections::HashSet<_> = c1.iter().collect();
        assert_eq!(unique.len(), c1.len());
    }

    #[test]
    fn committee_changes_across_rounds() {
        let b = HashChainBeacon::new([7u8; 32]);
        let relays = pool(20);
        let c_r5 = committee_for_round(&b, &relays, 5, 6);
        let c_r6 = committee_for_round(&b, &relays, 6, 6);
        assert_ne!(c_r5, c_r6, "committee should reshuffle across beacon rounds");
    }

    #[test]
    fn committee_size_clamped_to_pool_size() {
        let b = HashChainBeacon::new([3u8; 32]);
        let relays = pool(4);
        let c = committee_for_round(&b, &relays, 0, 10);
        assert_eq!(c.len(), 4);
    }
}
