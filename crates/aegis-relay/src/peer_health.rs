//! Per-peer link health sampling for [`aegis_trust::RelayPruningPolicy`].
//!
//! Each relay observes inbound/outbound handshake and send outcomes on its hop
//! links and feeds scalar failure rates into anomaly-driven pruning via
//! [`Self::drain_into_policy`]. Cross-relay signed gossip
//! ([`crate::health_gossip`]) can also contribute dampened remote observations
//! via [`Self::ingest_gossip_observation`] (lightweight majority / median merge
//! with optional org diversity + eclipse quarantine — **stacked** defense).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use aegis_trust::{feed_peer_outcomes, RelayPruningPolicy};

/// Distinct neighbor reporters required before gossip is merged (stacked default).
///
/// Raised from the legacy `2` toward sim S5 `raised_k` / `CI_DEFENSE_K = 4`.
/// `1` = lab immediate apply; `>=2` = lightweight majority (not BFT).
pub const DEFAULT_GOSSIP_MAJORITY_K: usize = 4;

/// Minimum distinct operator/org (or jurisdiction) labels inside a K-quorum.
///
/// `1` disables the diversity gate. Stacked default matches sim `CI_MIN_ORGS = 2`.
pub const DEFAULT_GOSSIP_MIN_ORGS: usize = 2;

/// When true, discard merges whose median failure rate looks eclipsed.
pub const DEFAULT_ECLIPSE_DETECT: bool = true;

/// Median fail-rate must exceed local/honest baseline by this gap to quarantine.
pub const DEFAULT_ECLIPSE_MEDIAN_GAP: f64 = 0.45;

/// Local samples required before using the subject's local fail-rate as baseline.
pub const DEFAULT_ECLIPSE_LOCAL_MIN_SAMPLES: u64 = 8;

/// Fallback honest fail-rate baseline when local samples are thin (sim twin).
pub const DEFAULT_ECLIPSE_HONEST_BASELINE: f64 = 0.10;

/// Gossip outcomes are applied at half weight (simple trust-of-reporter decay).
pub const GOSSIP_WEIGHT_NUM: u64 = 1;
pub const GOSSIP_WEIGHT_DEN: u64 = 2;

/// Tunable gossip merge policy (sim `stacked` = raised_k + diverse_org + eclipse_detect).
#[derive(Clone, Debug, PartialEq)]
pub struct GossipMergePolicy {
    /// Distinct reporters required before median merge.
    pub majority_k: usize,
    /// Distinct diversity keys (org / jurisdiction) required inside the quorum.
    pub min_orgs: usize,
    /// Quarantine high-gap / eclipsed medians instead of applying them.
    pub eclipse_detect: bool,
    /// `median_rate >= baseline + gap` → quarantine.
    pub eclipse_median_gap: f64,
    /// Local window samples required to use local fail-rate as baseline.
    pub eclipse_local_min_samples: u64,
    /// Baseline fail-rate when local samples are insufficient.
    pub eclipse_honest_baseline: f64,
}

impl Default for GossipMergePolicy {
    fn default() -> Self {
        Self::stacked()
    }
}

impl GossipMergePolicy {
    /// Production fail-safe: K=4, min_orgs=2, eclipse-detect on (sim `stacked`).
    pub fn stacked() -> Self {
        Self {
            majority_k: DEFAULT_GOSSIP_MAJORITY_K,
            min_orgs: DEFAULT_GOSSIP_MIN_ORGS,
            eclipse_detect: DEFAULT_ECLIPSE_DETECT,
            eclipse_median_gap: DEFAULT_ECLIPSE_MEDIAN_GAP,
            eclipse_local_min_samples: DEFAULT_ECLIPSE_LOCAL_MIN_SAMPLES,
            eclipse_honest_baseline: DEFAULT_ECLIPSE_HONEST_BASELINE,
        }
    }

    /// Legacy K-only merge (no diversity gate, no eclipse quarantine).
    pub fn legacy_majority(majority_k: usize) -> Self {
        Self {
            majority_k: majority_k.max(1),
            min_orgs: 1,
            eclipse_detect: false,
            eclipse_median_gap: DEFAULT_ECLIPSE_MEDIAN_GAP,
            eclipse_local_min_samples: DEFAULT_ECLIPSE_LOCAL_MIN_SAMPLES,
            eclipse_honest_baseline: DEFAULT_ECLIPSE_HONEST_BASELINE,
        }
    }

    pub fn sanitize(mut self) -> Self {
        self.majority_k = self.majority_k.max(1);
        self.min_orgs = self.min_orgs.max(1);
        if !self.eclipse_median_gap.is_finite() || self.eclipse_median_gap < 0.0 {
            self.eclipse_median_gap = DEFAULT_ECLIPSE_MEDIAN_GAP;
        }
        if !self.eclipse_honest_baseline.is_finite() {
            self.eclipse_honest_baseline = DEFAULT_ECLIPSE_HONEST_BASELINE;
        }
        self.eclipse_honest_baseline = self.eclipse_honest_baseline.clamp(0.0, 1.0);
        self
    }
}

/// Result of buffering / applying a verified gossip observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GossipMergeOutcome {
    /// Waiting for more distinct reporters (`have` of `need`).
    Buffered { have: usize, need: usize },
    /// K reporters present but fewer than `min_orgs` distinct diversity keys.
    WaitingDiversity {
        have: usize,
        distinct_orgs: usize,
        need_orgs: usize,
    },
    /// Quorum reached; median failure rate applied at half weight.
    Applied {
        reporters: usize,
        distinct_orgs: usize,
    },
    /// Quorum reached but merge discarded by eclipse-detect heuristic.
    Quarantined {
        reporters: usize,
        distinct_orgs: usize,
    },
}

/// Sliding window of inbound/outbound handshake and send outcomes keyed by peer relay id.
///
/// Thread-safe: recording uses a short-lived mutex; safe to share as `Arc` across
/// link-bridge tasks and a periodic drain loop in `aegis-node`.
pub struct PeerHealthTracker {
    inner: Mutex<HashMap<[u8; 32], (u64, u64)>>,
    /// subject → reporter → (successes, failures, diversity_key)
    gossip_pending: Mutex<HashMap<[u8; 32], HashMap<[u8; 32], (u64, u64, String)>>>,
    policy: GossipMergePolicy,
}

impl PeerHealthTracker {
    /// Minimum combined samples before a peer window is fed into the policy.
    pub const DEFAULT_MIN_SAMPLES: u64 = 4;

    pub fn new() -> Self {
        Self::with_policy(GossipMergePolicy::stacked())
    }

    /// Construct with a custom gossip majority `K` (legacy K-only semantics).
    ///
    /// Diversity gate and eclipse-detect are off so lab/tests that only set `K`
    /// keep prior behavior. Production should use [`Self::with_policy`].
    pub fn with_gossip_majority_k(majority_k: usize) -> Self {
        Self::with_policy(GossipMergePolicy::legacy_majority(majority_k))
    }

    /// Construct with a full merge policy (stacked / custom).
    pub fn with_policy(policy: GossipMergePolicy) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            gossip_pending: Mutex::new(HashMap::new()),
            policy: policy.sanitize(),
        }
    }

    pub fn gossip_majority_k(&self) -> usize {
        self.policy.majority_k
    }

    pub fn gossip_min_orgs(&self) -> usize {
        self.policy.min_orgs
    }

    pub fn eclipse_detect_enabled(&self) -> bool {
        self.policy.eclipse_detect
    }

    pub fn merge_policy(&self) -> &GossipMergePolicy {
        &self.policy
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
    /// reporters **and** `min_orgs` diversity keys are present.
    ///
    /// Lightweight majority — **not** BFT. Same reporter overwrites its prior
    /// observation for the subject. `diversity_key` is typically `org:…` or
    /// `jur:…` from peer config; unlabeled peers should pass a per-reporter key
    /// (availability fail-open).
    pub fn ingest_gossip_observation(
        &self,
        reporter: [u8; 32],
        subject: [u8; 32],
        successes: u64,
        failures: u64,
        diversity_key: impl Into<String>,
    ) -> GossipMergeOutcome {
        let key = normalize_diversity_key(diversity_key.into(), &reporter);
        let k = self.policy.majority_k;
        let min_orgs = self.policy.min_orgs;
        let mut pending = self.gossip_pending.lock().expect("gossip pending lock");
        let by_reporter = pending.entry(subject).or_default();
        by_reporter.insert(reporter, (successes, failures, key));
        let have = by_reporter.len();
        let distinct_orgs = distinct_diversity_count(by_reporter.values().map(|(_, _, d)| d.as_str()));
        if have < k {
            return GossipMergeOutcome::Buffered { have, need: k };
        }
        if distinct_orgs < min_orgs {
            return GossipMergeOutcome::WaitingDiversity {
                have,
                distinct_orgs,
                need_orgs: min_orgs,
            };
        }

        let observations: Vec<(u64, u64)> = by_reporter
            .values()
            .map(|&(ok, fail, _)| (ok, fail))
            .collect();
        by_reporter.clear();
        drop(pending);

        self.finish_median_merge(subject, &observations, have, distinct_orgs)
    }

    /// Apply a pre-formed quorum (used by [`crate::health_quorum_log`]).
    ///
    /// Caller has already enforced reporter `majority_k`. This gates on `min_orgs`
    /// and optional eclipse quarantine, then half-weight merges.
    pub fn apply_quorum_median(
        &self,
        subject: [u8; 32],
        observations: &[(u64, u64)],
        diversity_keys: &[String],
    ) -> GossipMergeOutcome {
        let reporters = observations.len();
        let distinct_orgs = distinct_diversity_count(diversity_keys.iter().map(|s| s.as_str()));
        let min_orgs = self.policy.min_orgs;
        if distinct_orgs < min_orgs {
            return GossipMergeOutcome::WaitingDiversity {
                have: reporters,
                distinct_orgs,
                need_orgs: min_orgs,
            };
        }
        self.finish_median_merge(subject, observations, reporters, distinct_orgs)
    }

    fn finish_median_merge(
        &self,
        subject: [u8; 32],
        observations: &[(u64, u64)],
        reporters: usize,
        distinct_orgs: usize,
    ) -> GossipMergeOutcome {
        let Some((ok, fail)) = median_outcome_counts(observations) else {
            return GossipMergeOutcome::Applied {
                reporters,
                distinct_orgs,
            };
        };
        let total = ok.saturating_add(fail).max(1);
        let median_rate = fail as f64 / total as f64;
        if self.policy.eclipse_detect && self.eclipse_heuristic_quarantine(subject, median_rate) {
            return GossipMergeOutcome::Quarantined {
                reporters,
                distinct_orgs,
            };
        }
        self.apply_gossip_outcomes(subject, ok, fail, GOSSIP_WEIGHT_NUM, GOSSIP_WEIGHT_DEN);
        GossipMergeOutcome::Applied {
            reporters,
            distinct_orgs,
        }
    }

    /// Sim twin of `eclipse_heuristic_quarantine` (no pure-adv oracle in product).
    pub fn eclipse_heuristic_quarantine(&self, subject: [u8; 32], median_rate: f64) -> bool {
        let (local_rate, local_samples) = {
            let guard = self.inner.lock().expect("peer health lock");
            match guard.get(&subject) {
                Some((ok, fail)) => {
                    let samples = ok.saturating_add(*fail);
                    if samples == 0 {
                        (None, 0u64)
                    } else {
                        (Some(*fail as f64 / samples as f64), samples)
                    }
                }
                None => (None, 0u64),
            }
        };
        let baseline = if local_rate.is_some() && local_samples >= self.policy.eclipse_local_min_samples
        {
            local_rate.unwrap()
        } else {
            self.policy.eclipse_honest_baseline
        };
        median_rate >= baseline + self.policy.eclipse_median_gap
    }

    /// Pending distinct reporters for `subject` (tests / diagnostics).
    pub fn pending_gossip_reporters(&self, subject: [u8; 32]) -> usize {
        let pending = self.gossip_pending.lock().expect("gossip pending lock");
        pending.get(&subject).map(|m| m.len()).unwrap_or(0)
    }

    /// Pending distinct diversity keys for `subject` (tests / diagnostics).
    pub fn pending_gossip_orgs(&self, subject: [u8; 32]) -> usize {
        let pending = self.gossip_pending.lock().expect("gossip pending lock");
        pending
            .get(&subject)
            .map(|m| distinct_diversity_count(m.values().map(|(_, _, d)| d.as_str())))
            .unwrap_or(0)
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

/// Build a diversity key from optional org / jurisdiction labels.
///
/// Prefer `org_id`, then `jurisdiction`. When both absent, use a per-reporter
/// key so unlabeled peers remain available (diversity is a no-op until labels
/// are configured — operators must set org/jurisdiction for the gate to bite).
pub fn gossip_diversity_key(
    org_id: Option<&str>,
    jurisdiction: Option<&str>,
    reporter: &[u8; 32],
) -> String {
    if let Some(org) = org_id.map(str::trim).filter(|s| !s.is_empty()) {
        return format!("org:{org}");
    }
    if let Some(jur) = jurisdiction.map(str::trim).filter(|s| !s.is_empty()) {
        return format!("jur:{jur}");
    }
    format!("rid:{}", hex32(reporter))
}

fn normalize_diversity_key(key: String, reporter: &[u8; 32]) -> String {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        format!("rid:{}", hex32(reporter))
    } else {
        trimmed.to_string()
    }
}

fn distinct_diversity_count<'a>(keys: impl Iterator<Item = &'a str>) -> usize {
    let set: HashSet<&str> = keys.collect();
    set.len()
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

    fn org_key(org: &str) -> String {
        format!("org:{org}")
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
        let out = tracker.ingest_gossip_observation(peer(1), subject, 0, 100, org_key("a"));
        assert_eq!(out, GossipMergeOutcome::Buffered { have: 1, need: 2 });
        assert!(tracker.failure_rate(subject).is_none());

        let out = tracker.ingest_gossip_observation(peer(2), subject, 90, 10, org_key("b"));
        assert_eq!(
            out,
            GossipMergeOutcome::Applied {
                reporters: 2,
                distinct_orgs: 2
            }
        );
        let rate = tracker.failure_rate(subject).unwrap();
        // median of 1.0 and 0.1 = 0.55; half-weight preserves ratio
        assert!((rate - 0.55).abs() < 0.02, "got {rate}");
    }

    #[test]
    fn majority_resists_single_malicious_spike() {
        let tracker = PeerHealthTracker::with_gossip_majority_k(3);
        let subject = peer(50);
        tracker.ingest_gossip_observation(peer(1), subject, 90, 10, org_key("a"));
        tracker.ingest_gossip_observation(peer(2), subject, 88, 12, org_key("b"));
        tracker.ingest_gossip_observation(peer(3), subject, 0, 100, org_key("c"));
        let rate = tracker.failure_rate(subject).unwrap();
        assert!(rate < 0.25, "median should damp malicious reporter, got {rate}");
        assert!(rate > 0.05, "median should reflect honest ~10%, got {rate}");
    }

    #[test]
    fn stacked_default_policy_matches_sim() {
        let p = GossipMergePolicy::stacked();
        assert_eq!(p.majority_k, 4);
        assert_eq!(p.min_orgs, 2);
        assert!(p.eclipse_detect);
        assert!((p.eclipse_median_gap - 0.45).abs() < f64::EPSILON);
        let tracker = PeerHealthTracker::new();
        assert_eq!(tracker.gossip_majority_k(), 4);
        assert_eq!(tracker.gossip_min_orgs(), 2);
        assert!(tracker.eclipse_detect_enabled());
    }

    #[test]
    fn min_orgs_waits_for_diversity() {
        let tracker = PeerHealthTracker::with_policy(GossipMergePolicy {
            majority_k: 2,
            min_orgs: 2,
            eclipse_detect: false,
            ..GossipMergePolicy::stacked()
        });
        let subject = peer(11);
        // Same org — K met but diversity not.
        let out = tracker.ingest_gossip_observation(peer(1), subject, 0, 100, org_key("evil"));
        assert_eq!(out, GossipMergeOutcome::Buffered { have: 1, need: 2 });
        let out = tracker.ingest_gossip_observation(peer(2), subject, 0, 100, org_key("evil"));
        assert_eq!(
            out,
            GossipMergeOutcome::WaitingDiversity {
                have: 2,
                distinct_orgs: 1,
                need_orgs: 2
            }
        );
        assert!(tracker.failure_rate(subject).is_none());
        assert_eq!(tracker.pending_gossip_reporters(subject), 2);

        // Cross-org honest reporter unlocks merge.
        let out = tracker.ingest_gossip_observation(peer(3), subject, 90, 10, org_key("honest"));
        assert_eq!(
            out,
            GossipMergeOutcome::Applied {
                reporters: 3,
                distinct_orgs: 2
            }
        );
        assert!(tracker.failure_rate(subject).is_some());
        assert_eq!(tracker.pending_gossip_reporters(subject), 0);
    }

    #[test]
    fn eclipse_detect_quarantines_high_gap_median() {
        let tracker = PeerHealthTracker::with_policy(GossipMergePolicy {
            majority_k: 2,
            min_orgs: 1,
            eclipse_detect: true,
            ..GossipMergePolicy::stacked()
        });
        let subject = peer(22);
        // Local honest baseline (~10% fail) with enough samples.
        for _ in 0..9 {
            tracker.record_success(subject);
        }
        tracker.record_failure(subject);
        assert!(tracker.failure_rate(subject).unwrap() < 0.2);

        let out = tracker.ingest_gossip_observation(peer(1), subject, 0, 100, org_key("a"));
        assert!(matches!(out, GossipMergeOutcome::Buffered { .. }));
        let out = tracker.ingest_gossip_observation(peer(2), subject, 0, 100, org_key("b"));
        assert_eq!(
            out,
            GossipMergeOutcome::Quarantined {
                reporters: 2,
                distinct_orgs: 2
            }
        );
        // Local window unchanged by quarantined gossip (still ~0.1).
        let rate = tracker.failure_rate(subject).unwrap();
        assert!(rate < 0.2, "quarantine must not apply attack median, got {rate}");
    }

    #[test]
    fn eclipse_detect_allows_near_baseline_median() {
        let tracker = PeerHealthTracker::with_policy(GossipMergePolicy {
            majority_k: 2,
            min_orgs: 1,
            eclipse_detect: true,
            ..GossipMergePolicy::stacked()
        });
        let subject = peer(23);
        for _ in 0..9 {
            tracker.record_success(subject);
        }
        tracker.record_failure(subject);

        tracker.ingest_gossip_observation(peer(1), subject, 90, 10, org_key("a"));
        let out = tracker.ingest_gossip_observation(peer(2), subject, 88, 12, org_key("b"));
        assert!(matches!(
            out,
            GossipMergeOutcome::Applied {
                reporters: 2,
                ..
            }
        ));
    }

    #[test]
    fn diversity_key_prefers_org_then_jurisdiction() {
        let r = peer(9);
        assert_eq!(
            gossip_diversity_key(Some("acme"), Some("US"), &r),
            "org:acme"
        );
        assert_eq!(
            gossip_diversity_key(None, Some("DE"), &r),
            "jur:DE"
        );
        let rid = gossip_diversity_key(None, None, &r);
        assert!(rid.starts_with("rid:"));
        assert!(rid.contains("09"));
    }
}
