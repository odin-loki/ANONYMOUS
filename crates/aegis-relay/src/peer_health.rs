//! Per-peer link health sampling for [`aegis_trust::RelayPruningPolicy`].
//!
//! Each relay observes inbound/outbound handshake and send outcomes on its hop
//! links and feeds scalar failure rates into anomaly-driven pruning via
//! [`Self::drain_into_policy`]. Cross-relay signed gossip
//! ([`crate::health_gossip`]) can also contribute dampened remote observations
//! via [`Self::ingest_gossip_observation`] (lightweight majority / median merge).

use std::collections::HashMap;
use std::sync::Mutex;

use aegis_trust::{feed_peer_outcomes, RelayPruningPolicy};

/// Distinct neighbor reporters required before gossip is merged (default).
///
/// `1` = legacy immediate apply; `>=2` = lightweight majority (not BFT).
pub const DEFAULT_GOSSIP_MAJORITY_K: usize = 2;

/// Gossip outcomes are applied at half weight (simple trust-of-reporter decay).
pub const GOSSIP_WEIGHT_NUM: u64 = 1;
pub const GOSSIP_WEIGHT_DEN: u64 = 2;

/// Result of buffering / applying a verified gossip observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipMergeOutcome {
    /// Waiting for more distinct reporters (`have` of `need`).
    Buffered { have: usize, need: usize },
    /// Quorum reached; median failure rate applied at half weight.
    Applied { reporters: usize },
}

/// Sliding window of inbound/outbound handshake and send outcomes keyed by peer relay id.
///
/// Thread-safe: recording uses a short-lived mutex; safe to share as `Arc` across
/// link-bridge tasks and a periodic drain loop in `aegis-node`.
pub struct PeerHealthTracker {
    inner: Mutex<HashMap<[u8; 32], (u64, u64)>>,
    /// subject → reporter → (successes, failures)
    gossip_pending: Mutex<HashMap<[u8; 32], HashMap<[u8; 32], (u64, u64)>>>,
    majority_k: usize,
}

impl PeerHealthTracker {
    /// Minimum combined samples before a peer window is fed into the policy.
    pub const DEFAULT_MIN_SAMPLES: u64 = 4;

    pub fn new() -> Self {
        Self::with_gossip_majority_k(DEFAULT_GOSSIP_MAJORITY_K)
    }

    /// Construct with a custom gossip majority `K` (distinct reporters before merge).
    pub fn with_gossip_majority_k(majority_k: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            gossip_pending: Mutex::new(HashMap::new()),
            majority_k: majority_k.max(1),
        }
    }

    pub fn gossip_majority_k(&self) -> usize {
        self.majority_k
    }

    /// Record a successful outbound send (or reconnect+send) to `peer`.
    pub fn record_success(&self, peer: [u8; 32]) {
        let mut guard = self.inner.lock().expect("peer health lock");
        let entry = guard.entry(peer).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
    }

    /// Record a failed outbound handshake or send (after retry) to `peer`.
    pub fn record_failure(&self, peer: [u8; 32]) {
        let mut guard = self.inner.lock().expect("peer health lock");
        let entry = guard.entry(peer).or_insert((0, 0));
        entry.1 = entry.1.saturating_add(1);
    }

    /// Merge a remote gossip observation with integer weight `num/den` (e.g. 1/2).
    ///
    /// Counts are floored after scaling; zero-total windows are ignored.
    pub fn apply_gossip_outcomes(
        &self,
        peer: [u8; 32],
        successes: u64,
        failures: u64,
        weight_num: u64,
        weight_den: u64,
    ) {
        if weight_den == 0 {
            return;
        }
        let ok = successes.saturating_mul(weight_num) / weight_den;
        let fail = failures.saturating_mul(weight_num) / weight_den;
        if ok == 0 && fail == 0 {
            return;
        }
        let mut guard = self.inner.lock().expect("peer health lock");
        let entry = guard.entry(peer).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(ok);
        entry.1 = entry.1.saturating_add(fail);
    }

    /// Buffer a verified gossip observation; apply median merge when `K` distinct
    /// reporters have reported on `subject`.
    ///
    /// Lightweight majority — **not** BFT. Same reporter overwrites its prior
    /// observation for the subject.
    pub fn ingest_gossip_observation(
        &self,
        reporter: [u8; 32],
        subject: [u8; 32],
        successes: u64,
        failures: u64,
    ) -> GossipMergeOutcome {
        let k = self.majority_k;
        let mut pending = self.gossip_pending.lock().expect("gossip pending lock");
        let by_reporter = pending.entry(subject).or_default();
        by_reporter.insert(reporter, (successes, failures));
        let have = by_reporter.len();
        if have < k {
            return GossipMergeOutcome::Buffered { have, need: k };
        }

        let observations: Vec<(u64, u64)> = by_reporter.values().copied().collect();
        by_reporter.clear();
        drop(pending);

        if let Some((ok, fail)) = median_outcome_counts(&observations) {
            self.apply_gossip_outcomes(subject, ok, fail, GOSSIP_WEIGHT_NUM, GOSSIP_WEIGHT_DEN);
        }
        GossipMergeOutcome::Applied { reporters: have }
    }

    /// Pending distinct reporters for `subject` (tests / diagnostics).
    pub fn pending_gossip_reporters(&self, subject: [u8; 32]) -> usize {
        let pending = self.gossip_pending.lock().expect("gossip pending lock");
        pending.get(&subject).map(|m| m.len()).unwrap_or(0)
    }

    /// Non-destructive snapshot of current windows (for gossip emission).
    pub fn snapshot(&self) -> Vec<([u8; 32], u64, u64)> {
        let guard = self.inner.lock().expect("peer health lock");
        guard
            .iter()
            .map(|(peer, (ok, fail))| (*peer, *ok, *fail))
            .collect()
    }

    /// Failure rate for `peer` over the current window, if any samples exist.
    pub fn failure_rate(&self, peer: [u8; 32]) -> Option<f64> {
        let guard = self.inner.lock().expect("peer health lock");
        guard.get(&peer).and_then(|(ok, fail)| {
            let total = ok.saturating_add(*fail);
            if total == 0 {
                None
            } else {
                Some(*fail as f64 / total as f64)
            }
        })
    }

    /// Success rate for `peer` over the current window, if any samples exist.
    ///
    /// Used by weighted fair inbound drain (`1.0 - failure_rate`).
    pub fn success_rate(&self, peer: [u8; 32]) -> Option<f64> {
        self.failure_rate(peer).map(|fail| 1.0 - fail)
    }

    /// Compute failure rates, feed them into `policy`, and reset drained windows.
    ///
    /// Peers with fewer than `min_samples` combined outcomes are skipped so a
    /// single transient error does not spike the anomaly detector.
    ///
    /// Returns the number of peers whose metrics were fed.
    pub fn drain_into_policy(
        &self,
        policy: &mut RelayPruningPolicy,
        min_samples: u64,
    ) -> usize {
        let mut guard = self.inner.lock().expect("peer health lock");
        let mut fed = 0usize;
        for (peer, (ok, fail)) in guard.iter_mut() {
            let successes = *ok;
            let failures = *fail;
            let total = successes.saturating_add(failures);
            if total < min_samples {
                continue;
            }
            feed_peer_outcomes(policy, *peer, successes, failures);
            *ok = 0;
            *fail = 0;
            fed += 1;
        }
        fed
    }
}

impl Default for PeerHealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Median failure rate → synthetic (successes, failures) using mean sample total.
pub(crate) fn median_outcome_counts(obs: &[(u64, u64)]) -> Option<(u64, u64)> {
    let mut rates = Vec::new();
    let mut totals = Vec::new();
    for &(ok, fail) in obs {
        let total = ok.saturating_add(fail);
        if total == 0 {
            continue;
        }
        rates.push(fail as f64 / total as f64);
        totals.push(total);
    }
    if rates.is_empty() {
        return None;
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = rates.len() / 2;
    let median_rate = if rates.len() % 2 == 1 {
        rates[mid]
    } else {
        (rates[mid - 1] + rates[mid]) / 2.0
    };
    let avg_total = (totals.iter().sum::<u64>() as f64) / (totals.len() as f64);
    let sample_total = avg_total.round().max(1.0) as u64;
    let fail = ((median_rate * sample_total as f64).round() as u64).min(sample_total);
    let ok = sample_total.saturating_sub(fail);
    if ok == 0 && fail == 0 {
        None
    } else {
        Some((ok, fail))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_trust::DEFAULT_PATH_REPUTATION_FLOOR;

    fn peer(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn failure_rate_over_window() {
        let tracker = PeerHealthTracker::new();
        assert!(tracker.failure_rate(peer(1)).is_none());
        for _ in 0..7 {
            tracker.record_success(peer(1));
        }
        for _ in 0..3 {
            tracker.record_failure(peer(1));
        }
        let rate = tracker.failure_rate(peer(1)).unwrap();
        assert!((rate - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn drain_skips_below_min_samples() {
        let tracker = PeerHealthTracker::new();
        tracker.record_failure(peer(2));
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        assert_eq!(
            tracker.drain_into_policy(&mut policy, PeerHealthTracker::DEFAULT_MIN_SAMPLES),
            0
        );
        assert!(tracker.failure_rate(peer(2)).is_some());
    }

    #[test]
    fn drain_updates_ledger_on_stable_window() {
        let tracker = PeerHealthTracker::new();
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        policy.ledger_mut().admit_new_relay(peer(5));
        let before = policy.ledger().score(peer(5)).0;

        for _ in 0..20 {
            for _ in 0..99 {
                tracker.record_success(peer(5));
            }
            tracker.record_failure(peer(5));
            tracker.drain_into_policy(&mut policy, 10);
        }

        assert!(
            policy.ledger().score(peer(5)).0 > before,
            "stable low failure windows should raise EWMA score"
        );
    }

    #[test]
    fn drain_resets_window_and_feeds_policy() {
        let tracker = PeerHealthTracker::new();
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();

        for _ in 0..100 {
            for _ in 0..99 {
                tracker.record_success(peer(9));
            }
            tracker.record_failure(peer(9));
            assert_eq!(
                tracker.drain_into_policy(&mut policy, 10),
                1,
                "stable low failure rate should feed once per drain"
            );
        }
        assert!(tracker.failure_rate(peer(9)).is_none(), "window reset after drain");

        for _ in 0..5 {
            tracker.record_success(peer(9));
        }
        for _ in 0..95 {
            tracker.record_failure(peer(9));
        }
        tracker.drain_into_policy(&mut policy, 10);
        assert!(
            !policy.is_eligible(peer(9), DEFAULT_PATH_REPUTATION_FLOOR),
            "sustained high failure rate after stable baseline should demote"
        );
    }

    #[test]
    fn majority_k2_buffers_then_applies_median() {
        let tracker = PeerHealthTracker::with_gossip_majority_k(2);
        let subject = peer(7);
        let out = tracker.ingest_gossip_observation(peer(1), subject, 0, 100);
        assert_eq!(out, GossipMergeOutcome::Buffered { have: 1, need: 2 });
        assert!(tracker.failure_rate(subject).is_none());

        let out = tracker.ingest_gossip_observation(peer(2), subject, 90, 10);
        assert_eq!(out, GossipMergeOutcome::Applied { reporters: 2 });
        let rate = tracker.failure_rate(subject).unwrap();
        // median of 1.0 and 0.1 = 0.55; half-weight preserves ratio
        assert!((rate - 0.55).abs() < 0.02, "got {rate}");
    }

    #[test]
    fn majority_resists_single_malicious_spike() {
        let tracker = PeerHealthTracker::with_gossip_majority_k(3);
        let subject = peer(50);
        tracker.ingest_gossip_observation(peer(1), subject, 90, 10);
        tracker.ingest_gossip_observation(peer(2), subject, 88, 12);
        tracker.ingest_gossip_observation(peer(3), subject, 0, 100);
        let rate = tracker.failure_rate(subject).unwrap();
        assert!(rate < 0.25, "median should damp malicious reporter, got {rate}");
        assert!(rate > 0.05, "median should reflect honest ~10%, got {rate}");
    }
}
