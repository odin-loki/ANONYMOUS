//! Per-packet path selection and compromise math (spec §4.5, §6).

use std::collections::HashMap;

use rand::Rng;
use rand_core::OsRng;

use crate::error::TopologyError;
use crate::guards::GuardSelector;
use crate::layers::Topology;
use crate::roster::RelayRoster;
use crate::types::{JurisdictionId, RelayId};

/// Full-path compromise probability: `f^L` (spec §4.5, §6).
pub fn path_compromise_probability(f: f64, l: usize) -> f64 {
    f.powi(l as i32)
}

/// Policy for jurisdiction diversity on a path or guard set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JurisdictionPolicy {
    /// Maximum relays from the same jurisdiction allowed on one path.
    pub max_per_jurisdiction: usize,
}

impl Default for JurisdictionPolicy {
    fn default() -> Self {
        Self {
            max_per_jurisdiction: 1,
        }
    }
}

/// Returns `true` when no jurisdiction appears more than `policy.max_per_jurisdiction` times.
pub fn path_satisfies_jurisdiction(
    path: &[RelayId],
    roster: &RelayRoster,
    policy: &JurisdictionPolicy,
) -> Result<bool, TopologyError> {
    let mut counts: HashMap<&JurisdictionId, usize> = HashMap::new();
    for id in path {
        let record = roster
            .get(*id)
            .ok_or(TopologyError::RelayNotFound { relay: *id })?;
        let count = counts.entry(&record.jurisdiction).or_insert(0);
        *count += 1;
        if *count > policy.max_per_jurisdiction {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Select one relay per layer using a fresh OS CSPRNG draw on every call.
///
/// Layer 1 uses the stable guard from `guards` when provided (spec §4.6); inner
/// hops (layers 2..L) are uniformly random per packet.
pub fn select_path(
    topology: &Topology,
    guards: Option<&GuardSelector>,
) -> Result<Vec<RelayId>, TopologyError> {
    let mut path = Vec::with_capacity(topology.layer_count);
    let mut rng = OsRng;

    for (layer_idx, layer) in topology.layers.iter().enumerate() {
        if layer.is_empty() {
            return Err(TopologyError::EmptyLayer {
                layer: layer_idx + 1,
                epoch: topology.epoch,
            });
        }

        let relay = if layer_idx == 0 {
            if let Some(g) = guards {
                g.primary_guard()
            } else {
                let idx = rng.gen_range(0..layer.len());
                layer[idx]
            }
        } else {
            let idx = rng.gen_range(0..layer.len());
            layer[idx]
        };

        path.push(relay);
    }

    Ok(path)
}

/// Like [`select_path`] but rejects paths that violate jurisdiction policy.
pub fn select_diverse_path(
    topology: &Topology,
    roster: &RelayRoster,
    guards: Option<&GuardSelector>,
    policy: &JurisdictionPolicy,
    max_attempts: usize,
) -> Result<Vec<RelayId>, TopologyError> {
    for _ in 0..max_attempts {
        let path = select_path(topology, guards)?;
        if path_satisfies_jurisdiction(&path, roster, policy)? {
            return Ok(path);
        }
    }
    Err(TopologyError::EmptyLayer {
        layer: 0,
        epoch: topology.epoch,
    })
}
