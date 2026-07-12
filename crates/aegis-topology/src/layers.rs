//! Stratified L-tier topology with stable per-epoch membership (spec §4.5).

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
