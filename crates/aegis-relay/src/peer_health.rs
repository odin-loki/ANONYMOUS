//! Per-peer link health sampling for [`aegis_trust::RelayPruningPolicy`].
//!
//! In a permissioned mixnet without cross-relay health gossip, each relay
//! observes inbound/outbound handshake and send outcomes on its hop links and
//! feeds scalar failure rates into anomaly-driven pruning via
//! [`Self::drain_into_policy`].

use std::collections::HashMap;
use std::sync::Mutex;

use aegis_trust::{feed_peer_outcomes, RelayPruningPolicy};

/// Sliding window of inbound/outbound handshake and send outcomes keyed by peer relay id.
///
/// Thread-safe: recording uses a short-lived mutex; safe to share as `Arc` across
/// link-bridge tasks and a periodic drain loop in `aegis-node`.
pub struct PeerHealthTracker {
    inner: Mutex<HashMap<[u8; 32], (u64, u64)>>,
}

impl PeerHealthTracker {
    /// Minimum combined samples before a peer window is fed into the policy.
    pub const DEFAULT_MIN_SAMPLES: u64 = 4;

    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
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

        // Establish a stable ~1% failure baseline (needs multiple detector observations).
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
}
