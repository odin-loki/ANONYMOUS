//! EWMA reputation scoring (spec §4.8: "ZK reputation (scoped, non-PQ)").
//!
//! This module implements the actual score bookkeeping — real, deterministic,
//! fully tested. It is deliberately NOT zero-knowledge; see [`crate::zk`] for
//! where privacy would be layered on top in a future pass.

use std::collections::HashMap;

use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum ReputationError {
    #[error("decay factor must be in (0, 1], got {0}")]
    InvalidDecay(f64),
    #[error("unknown relay")]
    UnknownRelay,
}

/// A reputation score in `[0.0, 1.0]`; 1.0 = perfect observed behavior so far.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct ReputationScore(pub f64);

impl ReputationScore {
    /// Default for relays with no ledger entry (never admitted via production path).
    pub const NEUTRAL: ReputationScore = ReputationScore(0.5);
    /// Starting score for relays admitted via [`ReputationLedger::admit_new_relay`].
    /// Below the 0.3 reputation floor used by guard/path selection in `aegis-topology`.
    pub const PROBATIONARY: ReputationScore = ReputationScore(0.1);

    fn clamp01(x: f64) -> f64 {
        x.clamp(0.0, 1.0)
    }
}

/// Per-relay EWMA reputation: `score' = decay * score + (1 - decay) * outcome`,
/// `outcome ∈ {0.0 (failure), 1.0 (success)}`. Larger `decay` -> longer memory
/// (slower to punish/forgive); smaller `decay` -> reacts fast to recent behavior.
pub struct ReputationLedger {
    decay: f64,
    scores: HashMap<[u8; 32], f64>,
}

impl ReputationLedger {
    /// `decay` in `(0, 1]`. Typical: 0.9–0.99 (slow-moving reputation, resists
    /// single-observation noise, consistent with the consortium/permissioned
    /// model where relays are long-lived, vetted entities, not throwaway Sybils).
    pub fn new(decay: f64) -> Result<Self, ReputationError> {
        if !(decay > 0.0 && decay <= 1.0) {
            return Err(ReputationError::InvalidDecay(decay));
        }
        Ok(Self {
            decay,
            scores: HashMap::new(),
        })
    }

    /// Current score, defaulting relays with no ledger entry to [`ReputationScore::NEUTRAL`].
    ///
    /// Relays seeded at admission via [`Self::admit_new_relay`] are not "unseen" — they
    /// return [`ReputationScore::PROBATIONARY`] until real outcomes move the EWMA.
    pub fn score(&self, relay: [u8; 32]) -> ReputationScore {
        ReputationScore(*self.scores.get(&relay).unwrap_or(&ReputationScore::NEUTRAL.0))
    }

    /// Seed a newly-admitted relay at [`ReputationScore::PROBATIONARY`].
    ///
    /// Idempotent when the relay already has a ledger entry (re-admission does not
    /// downgrade an established score).
    pub fn admit_new_relay(&mut self, relay: [u8; 32]) {
        self.scores
            .entry(relay)
            .or_insert(ReputationScore::PROBATIONARY.0);
    }

    fn update(&mut self, relay: [u8; 32], outcome: f64) {
        let prev = *self.scores.get(&relay).unwrap_or(&ReputationScore::NEUTRAL.0);
        let next = ReputationScore::clamp01(self.decay * prev + (1.0 - self.decay) * outcome);
        self.scores.insert(relay, next);
    }

    pub fn record_success(&mut self, relay: [u8; 32]) {
        self.update(relay, 1.0);
    }

    pub fn record_failure(&mut self, relay: [u8; 32]) {
        self.update(relay, 0.0);
    }

    /// Relays whose score has fallen below `threshold` — candidates for
    /// de-admission from [`aegis_topology`]'s `RelayRoster` (not wired up
    /// automatically; that integration is a future step, kept as a caller
    /// decision here since de-admission has consortium-governance implications
    /// beyond this crate's scope).
    pub fn below_threshold(&self, threshold: f64) -> Vec<[u8; 32]> {
        self.scores
            .iter()
            .filter(|(_, &s)| s < threshold)
            .map(|(id, _)| *id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn unseen_relay_is_neutral() {
        let ledger = ReputationLedger::new(0.9).unwrap();
        assert_eq!(ledger.score(relay(1)).0, 0.5);
    }

    #[test]
    fn admit_new_relay_starts_probationary() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        ledger.admit_new_relay(relay(1));
        assert_eq!(ledger.score(relay(1)).0, ReputationScore::PROBATIONARY.0);
        assert!(ledger.score(relay(1)).0 < 0.3);
    }

    #[test]
    fn admit_new_relay_does_not_downgrade_existing_score() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        for _ in 0..20 {
            ledger.record_success(relay(1));
        }
        let before = ledger.score(relay(1)).0;
        ledger.admit_new_relay(relay(1));
        assert_eq!(ledger.score(relay(1)).0, before);
    }

    #[test]
    fn probationary_relay_can_earn_above_floor() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        ledger.admit_new_relay(relay(1));
        for _ in 0..50 {
            ledger.record_success(relay(1));
        }
        assert!(ledger.score(relay(1)).0 >= 0.3);
    }

    #[test]
    fn repeated_success_raises_score_toward_one() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        for _ in 0..200 {
            ledger.record_success(relay(1));
        }
        assert!(ledger.score(relay(1)).0 > 0.95);
    }

    #[test]
    fn repeated_failure_lowers_score_toward_zero() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        for _ in 0..200 {
            ledger.record_failure(relay(1));
        }
        assert!(ledger.score(relay(1)).0 < 0.05);
    }

    #[test]
    fn score_stays_in_bounds() {
        let mut ledger = ReputationLedger::new(0.5).unwrap();
        for _ in 0..1000 {
            ledger.record_success(relay(1));
            ledger.record_failure(relay(2));
        }
        assert!((0.0..=1.0).contains(&ledger.score(relay(1)).0));
        assert!((0.0..=1.0).contains(&ledger.score(relay(2)).0));
    }

    #[test]
    fn below_threshold_flags_bad_relays_only() {
        let mut ledger = ReputationLedger::new(0.8).unwrap();
        for _ in 0..50 {
            ledger.record_success(relay(1));
            ledger.record_failure(relay(2));
        }
        let bad = ledger.below_threshold(0.3);
        assert!(bad.contains(&relay(2)));
        assert!(!bad.contains(&relay(1)));
    }

    #[test]
    fn invalid_decay_rejected() {
        assert!(ReputationLedger::new(0.0).is_err());
        assert!(ReputationLedger::new(1.5).is_err());
        assert!(ReputationLedger::new(1.0).is_ok());
    }
}
