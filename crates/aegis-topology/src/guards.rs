//! Stable vetted layered guards (spec §4.6) and exposure plateau math.
//!
//! **Production callers** should use [`GuardSelector::new_reputation_weighted_pruned`]
//! (or [`crate::path::build_bound_path_pruned_with_guards`] which constructs guards
//! internally). Unfiltered [`GuardSelector::new`] / [`GuardSelector::new_for_tests`]
//! exist only under `cfg(test)` or the `test-utils` feature (default off) for Sybil
//! science and residual-threat measurement.

use aegis_trust::policy::RelayPruningPolicy;
use aegis_trust::reputation::ReputationLedger;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::error::TopologyError;
use crate::layers::Topology;
use crate::pruning::relay_satisfies_pruning_policy;
use crate::types::RelayId;

/// Default guard-set size (`g`) matching the paper exposure plateau `1-(1-c)^g`.
pub const GUARD_SET_SIZE: u32 = 3;

/// How layer-1 is chosen from the held epoch guard set when building paths.
///
/// Production defaults to [`GuardPinMode::StickyPrimary`]: the primary stays fixed for
/// the epoch (GPA learns one entry); backups are available for failover / alternate
/// circuits. [`GuardPinMode::Rotate`] cycles across the set per packet index for
/// empirical plateau measurements that track `1-(1-c)^g`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum GuardPinMode {
    /// Always pin layer-1 to [`GuardSelector::primary_guard`] (default production).
    #[default]
    StickyPrimary,
    /// Rotate layer-1 across [`GuardSelector::guard_set`] by packet index.
    Rotate,
}

/// Guard selection parameters for one client across an epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardConfig {
    /// Number of stable layer-1 guards held for the epoch (used in exposure math as `g`).
    pub guard_count: u32,
    /// How path builders pin layer-1 from the held set.
    pub pin_mode: GuardPinMode,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            guard_count: GUARD_SET_SIZE,
            pin_mode: GuardPinMode::StickyPrimary,
        }
    }
}

/// Stable guard set for one client epoch. Layer-1 entry is NOT re-randomized uniformly
/// over all layer-1 relays; it is pinned from this held set of size `g` (default 3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardSelector {
    pub epoch: u64,
    /// Fixed guard relays for this epoch (selected from layer 1 at epoch start).
    pub guards: Vec<RelayId>,
    /// Pin policy for path builders (sticky primary vs rotate).
    pub pin_mode: GuardPinMode,
}

impl GuardSelector {
    /// Pick `config.guard_count` relays from topology layer 1 without reputation
    /// filtering — **test/lab only**.
    ///
    /// Available only under `cfg(test)` or the `test-utils` feature (default off).
    /// Production must use [`Self::new_reputation_weighted_pruned`] or
    /// [`crate::path::build_bound_path_pruned_with_guards`].
    #[cfg(any(test, feature = "test-utils"))]
    pub fn new_for_tests(
        topology: &Topology,
        config: &GuardConfig,
        client_seed: u64,
    ) -> Result<Self, TopologyError> {
        let layer1 = topology
            .layer(0)
            .ok_or(TopologyError::EmptyLayer {
                layer: 1,
                epoch: topology.epoch,
            })?;

        let needed = config.guard_count as usize;
        if layer1.len() < needed {
            return Err(TopologyError::InsufficientGuards {
                available: layer1.len(),
                needed,
            });
        }

        let mut candidates: Vec<RelayId> = layer1.to_vec();
        let mut rng = StdRng::seed_from_u64(
            client_seed
                .wrapping_mul(0x517c_c1b7_2722_0a95)
                .wrapping_add(topology.epoch),
        );

        // Partial Fisher–Yates to pick `needed` distinct guards.
        for i in 0..needed {
            let j = rng.gen_range(i..candidates.len());
            candidates.swap(i, j);
        }
        candidates.truncate(needed);

        Ok(Self {
            epoch: topology.epoch,
            guards: candidates,
            pin_mode: config.pin_mode,
        })
    }

    /// Unfiltered guard selection (no reputation floor).
    ///
    /// **Not compiled into production builds** of this crate unless the `test-utils`
    /// feature is enabled. Prefer [`Self::new_for_tests`] in new test code;
    /// production must use [`Self::new_reputation_weighted_pruned`] or
    /// [`crate::path::build_bound_path_pruned_with_guards`].
    #[cfg(any(test, feature = "test-utils"))]
    #[deprecated(
        note = "unfiltered guard selection is test-only; production must use new_reputation_weighted_pruned / build_bound_path_pruned_with_guards (enable feature aegis-topology/test-utils only in test deps)"
    )]
    pub fn new(
        topology: &Topology,
        config: &GuardConfig,
        client_seed: u64,
    ) -> Result<Self, TopologyError> {
        Self::new_for_tests(topology, config, client_seed)
    }

    /// Like [`Self::new`] but only considers layer-1 relays whose
    /// [`ReputationLedger`] score is at or above `min_reputation` before the
    /// deterministic random pick. Returns an error rather than admitting a
    /// sub-floor relay when too few candidates remain.
    pub fn new_reputation_weighted(
        topology: &Topology,
        config: &GuardConfig,
        client_seed: u64,
        ledger: &ReputationLedger,
        min_reputation: f64,
    ) -> Result<Self, TopologyError> {
        let layer1 = topology
            .layer(0)
            .ok_or(TopologyError::EmptyLayer {
                layer: 1,
                epoch: topology.epoch,
            })?;

        let needed = config.guard_count as usize;
        let candidates: Vec<RelayId> = layer1
            .iter()
            .copied()
            .filter(|id| ledger.score(*id.as_bytes()).0 >= min_reputation)
            .collect();

        if candidates.len() < needed {
            return Err(TopologyError::InsufficientReputation {
                available: candidates.len(),
                needed,
                min_reputation,
            });
        }

        let mut candidates = candidates;
        let mut rng = StdRng::seed_from_u64(
            client_seed
                .wrapping_mul(0x517c_c1b7_2722_0a95)
                .wrapping_add(topology.epoch),
        );

        for i in 0..needed {
            let j = rng.gen_range(i..candidates.len());
            candidates.swap(i, j);
        }
        candidates.truncate(needed);

        Ok(Self {
            epoch: topology.epoch,
            guards: candidates,
            pin_mode: config.pin_mode,
        })
    }

    /// Like [`Self::new_reputation_weighted`] but filters layer-1 candidates with
    /// [`RelayPruningPolicy::is_eligible`] at `min_reputation` (anomaly demotion).
    pub fn new_reputation_weighted_pruned(
        topology: &Topology,
        config: &GuardConfig,
        client_seed: u64,
        policy: &RelayPruningPolicy,
        min_reputation: f64,
    ) -> Result<Self, TopologyError> {
        let layer1 = topology
            .layer(0)
            .ok_or(TopologyError::EmptyLayer {
                layer: 1,
                epoch: topology.epoch,
            })?;

        let needed = config.guard_count as usize;
        let candidates: Vec<RelayId> = layer1
            .iter()
            .copied()
            .filter(|id| relay_satisfies_pruning_policy(*id, policy, min_reputation))
            .collect();

        if candidates.len() < needed {
            return Err(TopologyError::InsufficientReputation {
                available: candidates.len(),
                needed,
                min_reputation,
            });
        }

        let mut candidates = candidates;
        let mut rng = StdRng::seed_from_u64(
            client_seed
                .wrapping_mul(0x517c_c1b7_2722_0a95)
                .wrapping_add(topology.epoch),
        );

        for i in 0..needed {
            let j = rng.gen_range(i..candidates.len());
            candidates.swap(i, j);
        }
        candidates.truncate(needed);

        Ok(Self {
            epoch: topology.epoch,
            guards: candidates,
            pin_mode: config.pin_mode,
        })
    }

    /// Held epoch guard set of size `g` (default [`GUARD_SET_SIZE`]).
    pub fn guard_set(&self) -> &[RelayId] {
        &self.guards
    }

    /// Primary entry guard plus remaining backups (same order as [`Self::guard_set`]).
    pub fn primary_and_backups(&self) -> (RelayId, &[RelayId]) {
        let primary = self.guards[0];
        let backups = if self.guards.len() > 1 {
            &self.guards[1..]
        } else {
            &[]
        };
        (primary, backups)
    }

    /// Primary entry guard — sticky default for production path pinning.
    pub fn primary_guard(&self) -> RelayId {
        self.guards[0]
    }

    /// Layer-1 entry for `packet_index` under this selector's [`GuardPinMode`].
    ///
    /// - [`GuardPinMode::StickyPrimary`]: always `guards[0]`
    /// - [`GuardPinMode::Rotate`]: `guards[packet_index % g]`
    pub fn entry_guard_for_packet(&self, packet_index: u64) -> RelayId {
        match self.pin_mode {
            GuardPinMode::StickyPrimary => self.primary_guard(),
            GuardPinMode::Rotate => {
                let g = self.guards.len().max(1);
                self.guards[(packet_index as usize) % g]
            }
        }
    }

    /// True when any held guard is in `adversary` (set-exposure for g>1 plateau math).
    pub fn any_guard_compromised(&self, adversary: &std::collections::HashSet<RelayId>) -> bool {
        self.guards.iter().any(|id| adversary.contains(id))
    }
}

/// Guard exposure plateau: `1 - (1 - c)^g` (spec §6, §12).
///
/// `c` = effective per-relay compromise probability; `g` = number of guards in
/// rotation over the relevant time horizon.
///
/// ## Evidence-ledger reproduction (§12)
///
/// The ledger pins **~27% at c = 10%** and **~3% at c = 1%** without stating `g`
/// explicitly. With **`g = 3`** (the default [`GuardConfig::guard_count`]):
///
/// - `guard_exposure_plateau(0.10, 3) = 1 - 0.9³ ≈ 0.271` (~27%)
/// - `guard_exposure_plateau(0.01, 3) = 1 - 0.99³ ≈ 0.030` (~3%)
///
/// Vetting drives `c` from ~10% down to ~1%; holding `g` fixed collapses the plateau
/// accordingly — matching the spec's "27% plateau → ~3% plateau" narrative.
pub fn guard_exposure_plateau(c: f64, g: u32) -> f64 {
    1.0 - (1.0 - c).powi(g as i32)
}

#[cfg(test)]
mod tests {
    use aegis_trust::policy::{RelayPruningPolicy, DEFAULT_PATH_REPUTATION_FLOOR};
    use aegis_trust::reputation::ReputationLedger;

    use super::*;
    use crate::layers::build_topology;
    use crate::roster::RelayRoster;
    use crate::types::{test_relay_id, test_relay_record, RelayId, TopologyConfig};

    fn sample_roster(n: u64) -> RelayRoster {
        let mut roster = RelayRoster::new();
        for i in 0..n {
            roster.admit_for_tests(test_relay_record(i + 1, "US"));
        }
        roster
    }

    fn ledger_with_bad_relay(bad_id: RelayId, failures: usize) -> ReputationLedger {
        let mut ledger = ReputationLedger::new(0.5).unwrap();
        for _ in 0..failures {
            ledger.record_failure(*bad_id.as_bytes());
        }
        ledger
    }

    #[test]
    fn reputation_weighted_guard_excludes_sub_floor_relay() {
        let roster = sample_roster(12);
        let topo = build_topology(&roster, 1, &TopologyConfig::high_threat(), 0).unwrap();
        let bad = test_relay_id(1);
        let ledger = ledger_with_bad_relay(bad, 20);
        assert!(ledger.score(*bad.as_bytes()).0 < 0.3);

        let config = GuardConfig::default();
        for seed in 0..100u64 {
            let guards =
                GuardSelector::new_reputation_weighted(&topo, &config, seed, &ledger, 0.3).unwrap();
            assert!(
                !guards.guards.contains(&bad),
                "sub-floor relay must never be selected as guard"
            );
        }
    }

    #[test]
    fn reputation_weighted_guard_errors_when_too_few_candidates() {
        let roster = sample_roster(6);
        let topo = build_topology(&roster, 0, &TopologyConfig::standard(), 0).unwrap();
        let mut ledger = ReputationLedger::new(0.5).unwrap();
        for id in &topo.layers[0] {
            ledger.record_failure(*id.as_bytes());
        }

        let err = GuardSelector::new_reputation_weighted(
            &topo,
            &GuardConfig::default(),
            0,
            &ledger,
            0.3,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TopologyError::InsufficientReputation { needed: 3, .. }
        ));
    }

    #[test]
    #[allow(deprecated)]
    fn reputation_unaware_guard_selector_unchanged() {
        let roster = sample_roster(12);
        let topo = build_topology(&roster, 5, &TopologyConfig::high_threat(), 0).unwrap();
        let guards = GuardSelector::new(&topo, &GuardConfig::default(), 123).unwrap();
        assert_eq!(guards.guards.len(), 3);
        assert_eq!(guards.epoch, 5);
    }

    fn demote_via_anomaly(relay: RelayId) -> RelayPruningPolicy {
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for _ in 0..100 {
            policy.observe_metric(*relay.as_bytes(), 10.0);
        }
        policy.observe_metric(*relay.as_bytes(), 1000.0);
        assert!(
            !policy.is_eligible(*relay.as_bytes(), DEFAULT_PATH_REPUTATION_FLOOR),
            "anomaly demotion must push relay below path floor"
        );
        policy
    }

    #[test]
    fn pruned_guard_excludes_anomaly_demoted_relay() {
        let roster = sample_roster(12);
        let topo = build_topology(&roster, 1, &TopologyConfig::high_threat(), 0).unwrap();
        let bad = test_relay_id(1);
        let policy = demote_via_anomaly(bad);

        for seed in 0..100u64 {
            let guards = GuardSelector::new_reputation_weighted_pruned(
                &topo,
                &GuardConfig::default(),
                seed,
                &policy,
                DEFAULT_PATH_REPUTATION_FLOOR,
            )
            .unwrap();
            assert!(
                !guards.guards.contains(&bad),
                "demoted relay must never be selected as guard"
            );
        }
    }

    #[test]
    fn pruned_guard_errors_when_too_few_eligible_candidates() {
        let roster = sample_roster(6);
        let topo = build_topology(&roster, 0, &TopologyConfig::standard(), 0).unwrap();
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for id in &topo.layers[0] {
            for _ in 0..100 {
                policy.observe_metric(*id.as_bytes(), 10.0);
            }
            policy.observe_metric(*id.as_bytes(), 1000.0);
        }

        let err = GuardSelector::new_reputation_weighted_pruned(
            &topo,
            &GuardConfig::default(),
            0,
            &policy,
            DEFAULT_PATH_REPUTATION_FLOOR,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TopologyError::InsufficientReputation { needed: 3, .. }
        ));
    }
}
