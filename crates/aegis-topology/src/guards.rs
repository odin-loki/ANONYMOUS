//! Stable vetted layered guards (spec §4.6) and exposure plateau math.

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
