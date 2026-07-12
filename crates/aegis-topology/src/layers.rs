//! Stratified L-tier topology with stable per-epoch membership (spec §4.5).

use aegis_trust::reputation::ReputationLedger;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::error::TopologyError;
use crate::roster::RelayRoster;
use crate::types::{RelayId, TopologyConfig};

/// Fixed layer membership for one epoch. Only changes at epoch rollover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topology {
    pub epoch: u64,
    pub layer_count: usize,
    /// `layers[i]` = relays in layer `i + 1` (outermost entry = index 0).
    pub layers: Vec<Vec<RelayId>>,
}

impl Topology {
    pub fn layer(&self, index: usize) -> Option<&[RelayId]> {
        self.layers.get(index).map(Vec::as_slice)
    }
}

/// Assign admitted relays to `L` layers for `epoch`, deterministically from `epoch_seed`.
///
/// Membership is stable for the entire epoch; path selection re-randomizes per packet.
pub fn build_topology(
    roster: &RelayRoster,
    epoch: u64,
    config: &TopologyConfig,
    epoch_seed: u64,
) -> Result<Topology, TopologyError> {
    let layer_count = config.layer_count;
    if layer_count == 0 {
        return Err(TopologyError::InvalidLayerCount(0));
    }

    let relays = roster.admitted_sorted();
    if relays.is_empty() {
        return Err(TopologyError::EmptyRoster);
    }

    let mut ids: Vec<RelayId> = relays.into_iter().map(|r| r.id).collect();

    // Epoch-seeded shuffle: same (epoch, seed) -> same membership; different epoch -> reshuffle.
    let mut rng = StdRng::seed_from_u64(epoch_seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(epoch));
    for i in (1..ids.len()).rev() {
        let j = rng.gen_range(0..=i);
        ids.swap(i, j);
    }

    let mut layers: Vec<Vec<RelayId>> = (0..layer_count).map(|_| Vec::new()).collect();
    for (i, id) in ids.into_iter().enumerate() {
        layers[i % layer_count].push(id);
    }

    Ok(Topology {
        epoch,
        layer_count,
        layers,
    })
}

/// Like [`build_topology`] but only assigns relays whose [`ReputationLedger`] score
/// is at or above `min_reputation`. Persistently bad relays are excluded from layer
/// assignment for the epoch without mutating the underlying roster.
pub fn build_topology_reputation_filtered(
    roster: &RelayRoster,
    epoch: u64,
    config: &TopologyConfig,
    epoch_seed: u64,
    ledger: &ReputationLedger,
    min_reputation: f64,
) -> Result<Topology, TopologyError> {
    let layer_count = config.layer_count;
    if layer_count == 0 {
        return Err(TopologyError::InvalidLayerCount(0));
    }

    let relays = roster.admitted_sorted_above_reputation(ledger, min_reputation);
    if relays.is_empty() {
        return Err(TopologyError::EmptyRoster);
    }

    let mut ids: Vec<RelayId> = relays.into_iter().map(|r| r.id).collect();

    let mut rng = StdRng::seed_from_u64(epoch_seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(epoch));
    for i in (1..ids.len()).rev() {
        let j = rng.gen_range(0..=i);
        ids.swap(i, j);
    }

    let mut layers: Vec<Vec<RelayId>> = (0..layer_count).map(|_| Vec::new()).collect();
    for (i, id) in ids.into_iter().enumerate() {
        layers[i % layer_count].push(id);
    }

    Ok(Topology {
        epoch,
        layer_count,
        layers,
    })
}

#[cfg(test)]
mod tests {
    use aegis_trust::reputation::ReputationLedger;

    use super::*;
    use crate::types::{JurisdictionId, RelayId, RelayRecord};

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

    #[test]
    fn reputation_filtered_topology_excludes_sub_floor_relay() {
        let roster = sample_roster(12);
        let bad = RelayId::from_u64(1);
        let mut ledger = ReputationLedger::new(0.5).unwrap();
        for _ in 0..20 {
            ledger.record_failure(*bad.as_bytes());
        }
        assert!(ledger.score(*bad.as_bytes()).0 < 0.3);

        let topo = build_topology_reputation_filtered(
            &roster,
            0,
            &TopologyConfig::high_threat(),
            0,
            &ledger,
            0.3,
        )
        .unwrap();

        assert!(!topo.layers.iter().flatten().any(|id| *id == bad));
    }

    #[test]
    fn unfiltered_build_topology_unchanged() {
        let roster = sample_roster(12);
        let config = TopologyConfig::high_threat();
        let a = build_topology(&roster, 42, &config, 99).unwrap();
        let b = build_topology(&roster, 42, &config, 99).unwrap();
        assert_eq!(a, b);
    }
}
