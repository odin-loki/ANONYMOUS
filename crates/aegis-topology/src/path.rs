//! Per-packet path selection and compromise math (spec §4.5, §6).

use std::collections::HashMap;

use aegis_trust::reputation::ReputationLedger;
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

/// Returns `true` when every relay on `path` has a ledger score at or above `min_reputation`.
pub fn path_satisfies_reputation(
    path: &[RelayId],
    ledger: &ReputationLedger,
    min_reputation: f64,
) -> bool {
    path.iter()
        .all(|id| ledger.score(*id.as_bytes()).0 >= min_reputation)
}

/// Like [`select_path`] but rejects paths containing any relay below `min_reputation`.
///
/// Retries up to `max_attempts` with fresh CSPRNG draws (same pattern as
/// [`select_diverse_path`]). Jurisdiction diversity is **not** applied here;
/// compose with [`select_diverse_reputation_path`] when both constraints matter.
pub fn select_path_reputation_weighted(
    topology: &Topology,
    roster: &RelayRoster,
    guards: Option<&GuardSelector>,
    ledger: &ReputationLedger,
    min_reputation: f64,
    max_attempts: usize,
) -> Result<Vec<RelayId>, TopologyError> {
    for _ in 0..max_attempts {
        let path = select_path(topology, guards)?;
        for id in &path {
            roster
                .get(*id)
                .ok_or(TopologyError::RelayNotFound { relay: *id })?;
        }
        if path_satisfies_reputation(&path, ledger, min_reputation) {
            return Ok(path);
        }
    }
    Err(TopologyError::ReputationPathExhausted {
        attempts: max_attempts,
    })
}

/// Applies **both** jurisdiction diversity ([`path_satisfies_jurisdiction`]) and
/// reputation floor ([`path_satisfies_reputation`]) on each retry.
pub fn select_diverse_reputation_path(
    topology: &Topology,
    roster: &RelayRoster,
    guards: Option<&GuardSelector>,
    policy: &JurisdictionPolicy,
    ledger: &ReputationLedger,
    min_reputation: f64,
    max_attempts: usize,
) -> Result<Vec<RelayId>, TopologyError> {
    for _ in 0..max_attempts {
        let path = select_path(topology, guards)?;
        if !path_satisfies_reputation(&path, ledger, min_reputation) {
            continue;
        }
        if path_satisfies_jurisdiction(&path, roster, policy)? {
            return Ok(path);
        }
    }
    Err(TopologyError::ReputationPathExhausted {
        attempts: max_attempts,
    })
}

#[cfg(test)]
mod tests {
    use aegis_trust::reputation::ReputationLedger;

    use super::*;
    use crate::layers::build_topology;
    use crate::types::{JurisdictionId, RelayRecord, TopologyConfig};

    fn sample_roster(n: u64, jurisdictions: &[&str]) -> RelayRoster {
        let mut roster = RelayRoster::new();
        for i in 0..n {
            let j = jurisdictions[i as usize % jurisdictions.len()];
            roster.admit(RelayRecord {
                id: RelayId::from_u64(i + 1),
                jurisdiction: JurisdictionId::new(j),
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
    fn reputation_weighted_path_excludes_sub_floor_relay() {
        let roster = sample_roster(24, &["US", "DE", "FR", "UK", "JP", "CA"]);
        let topo = build_topology(&roster, 1, &TopologyConfig::high_threat(), 0).unwrap();
        let bad = RelayId::from_u64(1);
        let ledger = ledger_with_bad_relay(bad, 20);
        assert!(ledger.score(*bad.as_bytes()).0 < 0.3);

        for _ in 0..200 {
            let path = select_path_reputation_weighted(&topo, &roster, None, &ledger, 0.3, 50)
                .unwrap();
            assert!(
                !path.contains(&bad),
                "sub-floor relay must never appear on path"
            );
        }
    }

    #[test]
    fn reputation_unaware_path_selection_unchanged() {
        let roster = sample_roster(24, &["US", "DE", "FR", "UK", "JP", "CA"]);
        let topo = build_topology(&roster, 1, &TopologyConfig::high_threat(), 0).unwrap();
        let path = select_path(&topo, None).unwrap();
        assert_eq!(path.len(), 4);
    }
}
