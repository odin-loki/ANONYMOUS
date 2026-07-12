//! Stable vetted layered guards (spec §4.6) and exposure plateau math.

use aegis_trust::reputation::ReputationLedger;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::error::TopologyError;
use crate::layers::Topology;
use crate::types::RelayId;

/// Guard selection parameters for one client across an epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardConfig {
    /// Number of stable layer-1 guards held for the epoch (used in exposure math as `g`).
    pub guard_count: u32,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self { guard_count: 3 }
    }
}

/// Stable guard set for one client epoch. Layer-1 entry is NOT re-randomized per packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardSelector {
    pub epoch: u64,
    /// Fixed guard relays for this epoch (selected from layer 1 at epoch start).
    pub guards: Vec<RelayId>,
}

impl GuardSelector {
    /// Pick `config.guard_count` relays from topology layer 1, deterministically per
    /// `(client_seed, epoch)`. The primary guard (`guards[0]`) is used for every packet.
    pub fn new(
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
        })
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
        })
    }

    /// Primary entry guard — stable for all packets in this epoch.
    pub fn primary_guard(&self) -> RelayId {
        self.guards[0]
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
    use aegis_trust::reputation::ReputationLedger;

    use super::*;
    use crate::layers::build_topology;
    use crate::roster::RelayRoster;
    use crate::types::{JurisdictionId, RelayId, RelayRecord, TopologyConfig};

    fn sample_roster(n: u64) -> RelayRoster {
        let mut roster = RelayRoster::new();
        for i in 0..n {
            roster.admit(RelayRecord {
                id: RelayId::from_u64(i + 1),
                jurisdiction: JurisdictionId::new("US"),
            });
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
        let bad = RelayId::from_u64(1);
        let ledger = ledger_with_bad_relay(bad, 20);
        assert!(ledger.score(*bad.as_bytes()).0 < 0.3);

        let config = GuardConfig { guard_count: 3 };
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
    fn reputation_unaware_guard_selector_unchanged() {
        let roster = sample_roster(12);
        let topo = build_topology(&roster, 5, &TopologyConfig::high_threat(), 0).unwrap();
        let guards = GuardSelector::new(&topo, &GuardConfig::default(), 123).unwrap();
        assert_eq!(guards.guards.len(), 3);
        assert_eq!(guards.epoch, 5);
    }
}
