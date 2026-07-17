//! Anomaly-driven relay pruning policy (spec §4.8).
//!
//! Wires [`AnomalyDetector`] metric streams into [`ReputationLedger`] demotion so
//! topology path/guard selection can exclude misbehaving relays via
//! [`Self::is_eligible`] (same 0.3 floor as `aegis-topology` reputation paths).

use std::collections::HashMap;

use crate::anomaly::{AnomalyDetector, AnomalyVerdict};
use crate::reputation::{ReputationError, ReputationLedger};

/// Reputation floor used by default guard/path selection in `aegis-topology`.
pub const DEFAULT_PATH_REPUTATION_FLOOR: f64 = 0.3;

/// Maximum [`ReputationLedger::record_failure`] calls applied for one anomaly flag
/// (stops once score drops below the configured floor).
const MAX_ANOMALY_DEMOTION_STRIKES: u32 = 32;

/// Per-relay anomaly observation → reputation demotion policy.
///
/// Maintains one [`AnomalyDetector`] per relay for a scalar metric (drop rate,
/// latency, etc.). An anomalous verdict demotes the relay in the ledger until its
/// score falls below the path floor; [`Self::is_eligible`] is the hook for
/// guard/path filters.
pub struct RelayPruningPolicy {
    ledger: ReputationLedger,
    detectors: HashMap<[u8; 32], AnomalyDetector>,
    alpha: f64,
    z_threshold: f64,
}

impl RelayPruningPolicy {
    /// `decay` is the ledger EWMA decay; `alpha` / `z_threshold` configure each
    /// per-relay [`AnomalyDetector`].
    pub fn new(decay: f64, alpha: f64, z_threshold: f64) -> Result<Self, ReputationError> {
        Ok(Self {
            ledger: ReputationLedger::new(decay)?,
            detectors: HashMap::new(),
            alpha,
            z_threshold,
        })
    }

    /// Shared ledger (read-only) for topology reputation-weighted selection.
    pub fn ledger(&self) -> &ReputationLedger {
        &self.ledger
    }

    pub fn ledger_mut(&mut self) -> &mut ReputationLedger {
        &mut self.ledger
    }

    /// Feed one metric sample for `relay`; demotes on an anomalous verdict.
    pub fn observe_metric(&mut self, relay: [u8; 32], x: f64) -> AnomalyVerdict {
        let detector = self
            .detectors
            .entry(relay)
            .or_insert_with(|| AnomalyDetector::new(self.alpha, self.z_threshold));
        let verdict = detector.observe(x);
        if verdict.is_anomalous {
            self.demote_relay(relay, DEFAULT_PATH_REPUTATION_FLOOR);
        }
        verdict
    }

    /// Apply an externally computed verdict (e.g. from another detector instance).
    pub fn apply_verdict(&mut self, relay: [u8; 32], verdict: AnomalyVerdict) {
        if verdict.is_anomalous {
            self.demote_relay(relay, DEFAULT_PATH_REPUTATION_FLOOR);
        }
    }

    /// Whether `relay` may participate in reputation-filtered guard/path selection.
    ///
    /// Topology callers should use the `*_pruned` APIs in `aegis-topology` (`select_path_reputation_weighted_pruned`,
    /// `GuardSelector::new_reputation_weighted_pruned`, `RelayRoster::admit_*_pruned`) which invoke this hook;
    /// relays must still be fed metrics via [`Self::observe_metric`] for demotion to take effect.
    pub fn is_eligible(&self, relay: [u8; 32], min_reputation: f64) -> bool {
        self.ledger.score(relay).0 >= min_reputation
    }

    fn demote_relay(&mut self, relay: [u8; 32], floor: f64) {
        for _ in 0..MAX_ANOMALY_DEMOTION_STRIKES {
            if self.ledger.score(relay).0 < floor {
                break;
            }
            self.ledger.record_failure(relay);
        }
    }
}

/// Feed a scalar peer failure-rate sample into anomaly-driven pruning.
///
/// `fail_rate` is typically `failures / (successes + failures)` over a local
/// observation window (0.0 = perfect, 1.0 = all failures). Relays should prefer
/// [`aegis_relay::PeerHealthTracker::drain_into_policy`] for periodic batching.
pub fn feed_peer_metric(
    policy: &mut RelayPruningPolicy,
    peer: [u8; 32],
    fail_rate: f64,
) -> AnomalyVerdict {
    policy.observe_metric(peer, fail_rate)
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
    fn stable_observations_keep_relay_eligible() {
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for i in 0..200 {
            let x = 10.0 + ((i % 5) as f64 - 2.0) * 0.1;
            let v = policy.observe_metric(relay(1), x);
            assert!(!v.is_anomalous);
        }
        assert!(policy.is_eligible(relay(1), DEFAULT_PATH_REPUTATION_FLOOR));
    }

    #[test]
    fn spike_after_stable_history_demotes_below_floor() {
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for _ in 0..100 {
            policy.observe_metric(relay(7), 10.0);
        }
        assert!(policy.is_eligible(relay(7), DEFAULT_PATH_REPUTATION_FLOOR));

        let verdict = policy.observe_metric(relay(7), 1000.0);
        assert!(verdict.is_anomalous);

        assert!(
            !policy.is_eligible(relay(7), DEFAULT_PATH_REPUTATION_FLOOR),
            "anomalous relay must fall below path reputation floor"
        );
        assert!(policy.ledger().score(relay(7)).0 < DEFAULT_PATH_REPUTATION_FLOOR);
    }

    #[test]
    fn apply_verdict_demotes_without_observation() {
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for _ in 0..50 {
            policy.ledger_mut().record_success(relay(2));
        }
        assert!(policy.is_eligible(relay(2), DEFAULT_PATH_REPUTATION_FLOOR));

        policy.apply_verdict(
            relay(2),
            AnomalyVerdict {
                z_score: 5.0,
                is_anomalous: true,
            },
        );
        assert!(!policy.is_eligible(relay(2), DEFAULT_PATH_REPUTATION_FLOOR));
    }

    #[test]
    fn other_relays_unaffected_by_one_spike() {
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for _ in 0..100 {
            policy.observe_metric(relay(1), 10.0);
            policy.observe_metric(relay(2), 10.0);
        }
        policy.observe_metric(relay(1), 1000.0);
        assert!(!policy.is_eligible(relay(1), DEFAULT_PATH_REPUTATION_FLOOR));
        assert!(policy.is_eligible(relay(2), DEFAULT_PATH_REPUTATION_FLOOR));
    }

    #[test]
    fn feed_peer_metric_demotes_on_failure_rate_spike() {
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for _ in 0..100 {
            feed_peer_metric(&mut policy, relay(3), 0.01);
        }
        assert!(policy.is_eligible(relay(3), DEFAULT_PATH_REPUTATION_FLOOR));
        let verdict = feed_peer_metric(&mut policy, relay(3), 0.95);
        assert!(verdict.is_anomalous);
        assert!(!policy.is_eligible(relay(3), DEFAULT_PATH_REPUTATION_FLOOR));
    }
}
