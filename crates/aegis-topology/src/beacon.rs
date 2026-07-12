//! Public randomness beacon for cover scheduling + committee assignment (spec §4.7).
//!
//! Two implementations are provided:
//!
//! - [`ThresholdBeacon`] — production path. An `(n, t)`-threshold BLS committee
//!   (via [`blsttc`]) produces per-round partial signatures that combine into
//!   verifiable, unpredictable public randomness. Key generation uses a one-time
//!   trusted-dealer setup ([`ThresholdBeaconCommittee::dealer_setup`]); a fully
//!   distributed DKG without a trusted dealer is future work.
//!
//! - [`HashChainBeacon`] — fallback/dev-mode beacon for single-node testing. A
//!   single published seed deterministically derives round values. Provides
//!   verifiability but not threshold unpredictability or liveness under partial
//!   compromise.
//!
//! Explicitly OUT of scope, per spec §4.7: the beacon does **not** drive topology
//! churn (churn accelerates intersection, §4.5/§12) and does **not** drive path
//! determinism (path selection stays fresh-CSPRNG-random per [`crate::path`]).
//! Its only jobs here are cover-schedule timing and committee assignment.

use std::collections::BTreeMap;

use blsttc::{PublicKeySet, SecretKeySet, SecretKeyShare, SignatureShare};
use rand::Rng;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

use crate::types::RelayId;

/// A source of per-round public randomness.
pub trait Beacon {
    /// 32 bytes of public randomness for `round`. Must be deterministic for a
    /// given `(beacon instance, round)` so all parties agree without communicating.
    fn randomness(&self, round: u64) -> [u8; 32];
}

/// Errors from threshold beacon share collection and combination.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BeaconError {
    #[error("no signature shares collected for round {0}")]
    NoSharesForRound(u64),

    #[error("insufficient signature shares for combination")]
    InsufficientShares,

    #[error("invalid signature share from participant {0}")]
    InvalidShare(usize),

    #[error("combined threshold signature failed verification")]
    InvalidCombinedSignature,
}

/// Domain-separated message signed by beacon committee members for `round`.
pub fn beacon_round_message(round: u64) -> Vec<u8> {
    let mut msg = b"aegis-beacon-v1".to_vec();
    msg.extend_from_slice(&round.to_le_bytes());
    msg
}

fn hash_combined_signature(sig: &blsttc::Signature) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(sig.to_bytes());
    h.finalize().into()
}

/// Verifier-side threshold beacon: holds the committee public key set and collected
/// partial signatures per round.
#[derive(Clone)]
pub struct ThresholdBeacon {
    pk_set: PublicKeySet,
    shares_by_round: BTreeMap<u64, BTreeMap<usize, SignatureShare>>,
}

impl ThresholdBeacon {
    pub fn new(pk_set: PublicKeySet) -> Self {
        Self {
            pk_set,
            shares_by_round: BTreeMap::new(),
        }
    }

    pub fn public_key_set(&self) -> &PublicKeySet {
        &self.pk_set
    }

    /// Record partial signatures for a round (verifier side, as shares arrive).
    pub fn add_shares(
        &mut self,
        round: u64,
        shares: impl IntoIterator<Item = (usize, SignatureShare)>,
    ) {
        let entry = self.shares_by_round.entry(round).or_default();
        for (index, share) in shares {
            entry.insert(index, share);
        }
    }

    /// Build a beacon with a complete quorum of shares for one round.
    pub fn from_quorum(
        pk_set: PublicKeySet,
        round: u64,
        shares: BTreeMap<usize, SignatureShare>,
    ) -> Self {
        let mut beacon = Self::new(pk_set);
        beacon.add_shares(round, shares);
        beacon
    }

    /// Combine collected shares for `round` and hash to 32-byte randomness.
    pub fn randomness_result(&self, round: u64) -> Result<[u8; 32], BeaconError> {
        let shares = self
            .shares_by_round
            .get(&round)
            .ok_or(BeaconError::NoSharesForRound(round))?;

        let msg = beacon_round_message(round);
        for (index, share) in shares {
            if !self
                .pk_set
                .public_key_share(*index)
                .verify(share, &msg)
            {
                return Err(BeaconError::InvalidShare(*index));
            }
        }

        let combined = self
            .pk_set
            .combine_signatures(shares.iter().map(|(i, s)| (*i, s)))
            .map_err(|_| BeaconError::InsufficientShares)?;

        if !self.pk_set.public_key().verify(&combined, &msg) {
            return Err(BeaconError::InvalidCombinedSignature);
        }

        Ok(hash_combined_signature(&combined))
    }
}

impl Beacon for ThresholdBeacon {
    fn randomness(&self, round: u64) -> [u8; 32] {
        self.randomness_result(round)
            .expect("threshold beacon missing quorum shares for round")
    }
}

/// Participant-side beacon committee member holding one threshold secret share.
#[derive(Clone)]
pub struct BeaconParticipant {
    index: usize,
    sk_share: SecretKeyShare,
}

impl BeaconParticipant {
    pub fn index(&self) -> usize {
        self.index
    }

    /// Produce a partial BLS signature for `round`.
    pub fn sign_round(&self, round: u64) -> SignatureShare {
        self.sk_share.sign(beacon_round_message(round))
    }
}

/// One-time dealer-based setup for an `(n, t)` threshold beacon committee.
///
/// `n` is the committee size; `t` is the reconstruction threshold (minimum shares
/// required to produce randomness). Uses `blsttc::SecretKeySet::random(t - 1, rng)`:
/// the crate's internal parameter is `t - 1`, meaning any `t` shares suffice.
#[derive(Clone)]
pub struct ThresholdBeaconCommittee {
    pub pk_set: PublicKeySet,
    participants: Vec<BeaconParticipant>,
    /// Minimum shares required to produce randomness (`t` in an `(n, t)` scheme).
    pub reconstruction_threshold: usize,
    /// Committee size `n`.
    pub committee_size: usize,
}

impl ThresholdBeaconCommittee {
    pub fn dealer_setup(n: usize, t: usize, rng: &mut impl Rng) -> Self {
        assert!(t >= 1, "reconstruction threshold must be at least 1");
        assert!(t <= n, "reconstruction threshold cannot exceed committee size");

        let sk_set = SecretKeySet::random(t - 1, rng);
        let pk_set = sk_set.public_keys();
        let participants = (0..n)
            .map(|i| BeaconParticipant {
                index: i,
                sk_share: sk_set.secret_key_share(i),
            })
            .collect();

        Self {
            pk_set,
            participants,
            reconstruction_threshold: t,
            committee_size: n,
        }
    }

    pub fn participant(&self, index: usize) -> &BeaconParticipant {
        &self.participants[index]
    }

    pub fn participants(&self) -> &[BeaconParticipant] {
        &self.participants
    }

    /// Collect partial signatures from `indices` and build a verifier-side beacon.
    pub fn build_beacon_for_round(
        &self,
        round: u64,
        indices: &[usize],
    ) -> Result<ThresholdBeacon, BeaconError> {
        let msg = beacon_round_message(round);
        let mut shares = BTreeMap::new();
        for &i in indices {
            let share = self.participants[i].sign_round(round);
            if !self.pk_set.public_key_share(i).verify(&share, &msg) {
                return Err(BeaconError::InvalidShare(i));
            }
            shares.insert(i, share);
        }
        Ok(ThresholdBeacon::from_quorum(self.pk_set.clone(), round, shares))
    }
}

/// Fallback beacon: `value(r) = SHA3-256(domain || seed || r)`.
///
/// Verifiable by anyone holding `seed`. **Single-authority, not threshold-distributed**
/// — use only for dev/single-node testing; see module docs.
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
    use rand::thread_rng;

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

    #[test]
    fn threshold_beacon_three_of_five_produces_randomness() {
        let mut rng = thread_rng();
        let committee = ThresholdBeaconCommittee::dealer_setup(5, 3, &mut rng);
        let round = 42u64;

        let beacon = committee
            .build_beacon_for_round(round, &[0, 1, 2])
            .expect("quorum of 3");

        let r1 = beacon.randomness(round);
        let r2 = beacon.randomness_result(round).expect("combine");
        assert_eq!(r1, r2);
        assert_ne!(r1, [0u8; 32]);
    }

    #[test]
    fn threshold_beacon_different_quorums_same_round_match() {
        let mut rng = thread_rng();
        let committee = ThresholdBeaconCommittee::dealer_setup(5, 3, &mut rng);
        let round = 7u64;

        let b_a = committee
            .build_beacon_for_round(round, &[0, 1, 2])
            .expect("quorum A");
        let b_b = committee
            .build_beacon_for_round(round, &[2, 3, 4])
            .expect("quorum B");

        assert_eq!(b_a.randomness(round), b_b.randomness(round));
    }

    #[test]
    fn threshold_beacon_insufficient_shares_error() {
        let mut rng = thread_rng();
        let committee = ThresholdBeaconCommittee::dealer_setup(5, 3, &mut rng);
        let round = 1u64;

        let beacon = committee
            .build_beacon_for_round(round, &[0, 1])
            .expect("two shares collected");
        let err = beacon.randomness_result(round).unwrap_err();
        assert_eq!(err, BeaconError::InsufficientShares);
    }

    #[test]
    fn threshold_beacon_different_rounds_differ() {
        let mut rng = thread_rng();
        let committee = ThresholdBeaconCommittee::dealer_setup(5, 3, &mut rng);

        let b_r10 = committee
            .build_beacon_for_round(10, &[0, 1, 2])
            .expect("round 10");
        let b_r11 = committee
            .build_beacon_for_round(11, &[0, 1, 2])
            .expect("round 11");

        assert_ne!(b_r10.randomness(10), b_r11.randomness(11));
    }

    #[test]
    fn threshold_beacon_tampered_share_rejected() {
        let mut rng = thread_rng();
        let committee = ThresholdBeaconCommittee::dealer_setup(5, 3, &mut rng);
        let round = 99u64;
        let msg = beacon_round_message(round);

        let mut shares = BTreeMap::new();
        for i in 0..3 {
            shares.insert(i, committee.participant(i).sign_round(round));
        }

        // Replace one share with a signature over a different message.
        let bad_share = committee.participant(3).sign_round(round + 1);
        shares.insert(1, bad_share);

        let beacon = ThresholdBeacon::from_quorum(committee.pk_set.clone(), round, shares);
        let err = beacon.randomness_result(round).unwrap_err();
        assert!(
            matches!(
                err,
                BeaconError::InvalidShare(1) | BeaconError::InvalidCombinedSignature
            ),
            "tampered share should fail verification, got {err:?}"
        );

        // Sanity: valid shares still verify individually before tamper.
        let good = committee.participant(1).sign_round(round);
        assert!(committee.pk_set.public_key_share(1).verify(&good, &msg));
    }
}
