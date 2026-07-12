//! Batched-bulk-round scheduler (spec §5.4).
//!
//! Endpoints opt into beacon-timed rounds via anonymous commitments without revealing
//! their partner. The scheduler manufactures the bulk anonymity set by batching
//! independent opt-ins into the same round index.

use std::collections::HashMap;

/// Beacon-timed round index for a wall-clock instant.
///
/// Round `r` covers `[r × period, (r+1) × period)`. Times exactly on a boundary
/// belong to the next round.
#[must_use]
pub fn next_round(current_time_s: f64, round_period_s: f64) -> u64 {
    assert!(round_period_s > 0.0, "round_period_s must be positive");
    assert!(current_time_s.is_finite(), "current_time_s must be finite");
    (current_time_s / round_period_s).floor() as u64
}

/// In-memory batching scheduler: collects anonymous per-round commitments.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BatchScheduler {
    rounds: HashMap<u64, Vec<[u8; 32]>>,
}

impl BatchScheduler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an anonymous opt-in commitment for a beacon round.
    pub fn opt_in(&mut self, participant_commitment: [u8; 32], round: u64) {
        self.rounds
            .entry(round)
            .or_default()
            .push(participant_commitment);
    }

    /// All participant commitments batched into `round` (the manufactured anonymity set).
    #[must_use]
    pub fn round_participants(&self, round: u64) -> Vec<[u8; 32]> {
        self.rounds.get(&round).cloned().unwrap_or_default()
    }

    /// Number of independent participants in `round`.
    #[must_use]
    pub fn round_size(&self, round: u64) -> usize {
        self.rounds.get(&round).map_or(0, Vec::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_round_boundaries() {
        let period = 60.0;
        assert_eq!(next_round(0.0, period), 0);
        assert_eq!(next_round(59.999, period), 0);
        assert_eq!(next_round(60.0, period), 1);
        assert_eq!(next_round(119.999, period), 1);
        assert_eq!(next_round(120.0, period), 2);
    }

    #[test]
    fn next_round_fractional_time() {
        assert_eq!(next_round(30.5, 60.0), 0);
        assert_eq!(next_round(90.0, 60.0), 1);
    }

    #[test]
    fn batch_scheduler_groups_by_round() {
        let mut sched = BatchScheduler::new();
        let c1 = [1u8; 32];
        let c2 = [2u8; 32];
        let c3 = [3u8; 32];
        sched.opt_in(c1, 0);
        sched.opt_in(c2, 0);
        sched.opt_in(c3, 1);
        assert_eq!(sched.round_size(0), 2);
        assert_eq!(sched.round_size(1), 1);
        assert_eq!(sched.round_size(2), 0);
        assert_eq!(sched.round_participants(0), vec![c1, c2]);
        assert_eq!(sched.round_participants(1), vec![c3]);
    }

    #[test]
    fn batch_scheduler_preserves_commitments() {
        let mut sched = BatchScheduler::new();
        let c = [0xAB; 32];
        sched.opt_in(c, 5);
        assert_eq!(sched.round_participants(5), vec![c]);
    }
}
