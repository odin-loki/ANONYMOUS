//! Per-packet path selection and compromise math (spec §4.5, §6).
//!
//! **Production callers** should use [`build_bound_path_pruned_with_guards`] or the
//! `*_reputation_weighted_pruned` helpers. Unfiltered [`select_path_for_tests`] /
//! [`select_path_indexed_for_tests`] exist only under `cfg(test)` or the `test-utils`
//! feature (default off) for Sybil science and residual-threat measurement.

use std::collections::HashMap;

use aegis_trust::reputation::ReputationLedger;
use rand::Rng;
use rand_core::OsRng;

use aegis_trust::policy::RelayPruningPolicy;

use crate::error::TopologyError;
use crate::guards::{GuardConfig, GuardSelector};
use crate::guard_mitigation::{GuardMitigationPolicy, GuardMitigationSignals};
use crate::layers::Topology;
use crate::pruning::path_satisfies_pruning_policy;
use crate::roster::RelayRoster;
use crate::types::{JurisdictionId, RelayId, RelayRecord};

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

/// Core path selection: one relay per layer using a fresh OS CSPRNG draw on every call.
///
/// Layer 1 is pinned from the held guard set when `guards` is provided
/// ([`GuardSelector::entry_guard_for_packet`]). Inner hops (layers 2..L) are uniformly
/// random per packet. Used internally by reputation-weighted and pruned path builders.
pub(crate) fn select_path_indexed_impl(
    topology: &Topology,
    guards: Option<&GuardSelector>,
    packet_index: u64,
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
                g.entry_guard_for_packet(packet_index)
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

/// Select one relay per layer without reputation filtering — **test/lab only**.
///
/// Layer 1 is pinned from the held guard set when `guards` is provided
/// ([`GuardSelector::entry_guard_for_packet`] with index 0 — sticky primary by
/// default). Inner hops (layers 2..L) are uniformly random per packet.
///
/// Available only under `cfg(test)` or the `test-utils` feature (default off).
/// Production must use [`build_bound_path_pruned_with_guards`] or
/// [`select_path_reputation_weighted_pruned`].
///
/// For rotate pinning across the g-set, use [`select_path_indexed_for_tests`].
#[cfg(any(test, feature = "test-utils"))]
pub fn select_path_for_tests(
    topology: &Topology,
    guards: Option<&GuardSelector>,
) -> Result<Vec<RelayId>, TopologyError> {
    select_path_indexed_for_tests(topology, guards, 0)
}

/// Unfiltered path selection (no reputation floor).
///
/// **Not compiled into production builds** of this crate unless the `test-utils`
/// feature is enabled. Prefer [`select_path_for_tests`] in new test code; production
/// must use [`build_bound_path_pruned_with_guards`] or
/// [`select_path_reputation_weighted_pruned`].
#[cfg(any(test, feature = "test-utils"))]
#[deprecated(
    note = "unfiltered path selection is test-only; production must use build_bound_path_pruned_with_guards / select_path_reputation_weighted_pruned (enable feature aegis-topology/test-utils only in test deps)"
)]
pub fn select_path(
    topology: &Topology,
    guards: Option<&GuardSelector>,
) -> Result<Vec<RelayId>, TopologyError> {
    select_path_for_tests(topology, guards)
}

/// Like [`select_path_for_tests`] but pins layer-1 with `packet_index` under the
/// selector's [`crate::guards::GuardPinMode`] (sticky primary or rotate across the g-set).
#[cfg(any(test, feature = "test-utils"))]
pub fn select_path_indexed_for_tests(
    topology: &Topology,
    guards: Option<&GuardSelector>,
    packet_index: u64,
) -> Result<Vec<RelayId>, TopologyError> {
    select_path_indexed_impl(topology, guards, packet_index)
}

/// Unfiltered indexed path selection — **test/lab only** (deprecated alias).
#[cfg(any(test, feature = "test-utils"))]
#[deprecated(
    note = "unfiltered path selection is test-only; production must use build_bound_path_pruned_with_guards / select_path_reputation_weighted_pruned (enable feature aegis-topology/test-utils only in test deps)"
)]
pub fn select_path_indexed(
    topology: &Topology,
    guards: Option<&GuardSelector>,
    packet_index: u64,
) -> Result<Vec<RelayId>, TopologyError> {
    select_path_indexed_for_tests(topology, guards, packet_index)
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
        let path = select_path_indexed_impl(topology, guards, 0)?;
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
        let path = select_path_indexed_impl(topology, guards, 0)?;
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
        let path = select_path_indexed_impl(topology, guards, 0)?;
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

/// Like [`select_path_reputation_weighted`] but also rejects any hop that fails
/// [`RelayPruningPolicy::is_eligible`] at `min_reputation` (anomaly demotion).
pub fn select_path_reputation_weighted_pruned(
    topology: &Topology,
    roster: &RelayRoster,
    guards: Option<&GuardSelector>,
    policy: &RelayPruningPolicy,
    min_reputation: f64,
    max_attempts: usize,
) -> Result<Vec<RelayId>, TopologyError> {
    for _ in 0..max_attempts {
        let path = select_path_indexed_impl(topology, guards, 0)?;
        for id in &path {
            roster
                .get(*id)
                .ok_or(TopologyError::RelayNotFound { relay: *id })?;
        }
        if path_satisfies_pruning_policy(&path, policy, min_reputation) {
            return Ok(path);
        }
    }
    Err(TopologyError::ReputationPathExhausted {
        attempts: max_attempts,
    })
}

/// Resolve each hop on `path` to an admitted [`RelayRecord`] (includes signed KEM commitment).
pub fn relay_records_for_path(
    path: &[RelayId],
    roster: &RelayRoster,
) -> Result<Vec<RelayRecord>, TopologyError> {
    path.iter()
        .map(|id| {
            roster
                .get(*id)
                .cloned()
                .ok_or(TopologyError::RelayNotFound { relay: *id })
        })
        .collect()
}

/// Production helper: pruned path selection plus roster record lookup with KEM commitments.
///
/// Composes [`select_path_reputation_weighted_pruned`] and [`relay_records_for_path`].
/// Layer-1 is pinned from the caller's multi-guard set (`g` = [`crate::guards::GUARD_SET_SIZE`]
/// by default) via sticky primary / rotate — never a fresh uniform layer-1 draw when
/// `guards` is `Some`. Callers attach live KEM public keys in `aegis-client` via
/// `hops_from_bound_path`.
///
/// Prefer [`build_bound_path_pruned_with_guards`] when the client should also construct
/// a reputation-weighted g-set rather than passing a pre-built selector.
pub fn build_bound_path_pruned(
    topology: &Topology,
    roster: &RelayRoster,
    guards: Option<&GuardSelector>,
    policy: &RelayPruningPolicy,
    min_reputation: f64,
    max_attempts: usize,
) -> Result<Vec<RelayRecord>, TopologyError> {
    let path = select_path_reputation_weighted_pruned(
        topology,
        roster,
        guards,
        policy,
        min_reputation,
        max_attempts,
    )?;
    relay_records_for_path(&path, roster)
}

/// Production default: build a reputation-weighted multi-guard set (`g` =
/// [`GuardConfig::default`] = 3) then a pruned bound path pinned to that set.
///
/// This is the recommended production entry point — multi-guard + reputation
/// filtering together. Unfiltered path/guard APIs are gated behind `test-utils`.
pub fn build_bound_path_pruned_with_guards(
    topology: &Topology,
    roster: &RelayRoster,
    client_seed: u64,
    policy: &RelayPruningPolicy,
    min_reputation: f64,
    max_attempts: usize,
) -> Result<(GuardSelector, Vec<RelayRecord>), TopologyError> {
    let config = GuardConfig::default();
    let guards = GuardSelector::new_reputation_weighted_pruned(
        topology,
        &config,
        client_seed,
        policy,
        min_reputation,
    )?;
    let records = build_bound_path_pruned(
        topology,
        roster,
        Some(&guards),
        policy,
        min_reputation,
        max_attempts,
    )?;
    Ok((guards, records))
}

/// Production path builder with adaptive guard mitigation applied before guard selection.
///
/// Applies [`GuardMitigationPolicy::apply_to_config_with_signals`] for pin mode and
/// [`GuardMitigationPolicy::client_seed_for_guards`] when re-sample is required.
/// Pass [`GuardMitigationSignals::default()`] when no epoch/anomaly telemetry is available yet.
pub fn build_bound_path_pruned_with_guards_mitigated(
    topology: &Topology,
    roster: &RelayRoster,
    base_guard_config: &GuardConfig,
    client_seed: u64,
    mitigation: &GuardMitigationPolicy,
    signals: &GuardMitigationSignals,
    policy: &RelayPruningPolicy,
    min_reputation: f64,
    max_attempts: usize,
) -> Result<(GuardSelector, Vec<RelayRecord>), TopologyError> {
    let guard_config = mitigation.apply_to_config_with_signals(base_guard_config, signals);
    let effective_seed = mitigation.client_seed_for_guards(client_seed, signals);
    let guards = GuardSelector::new_reputation_weighted_pruned(
        topology,
        &guard_config,
        effective_seed,
        policy,
        min_reputation,
    )?;
    let records = build_bound_path_pruned(
        topology,
        roster,
        Some(&guards),
        policy,
        min_reputation,
        max_attempts,
    )?;
    Ok((guards, records))
}

/// Like [`build_bound_path_pruned`] but also enforces jurisdiction diversity.
pub fn build_bound_path_diverse_pruned(
    topology: &Topology,
    roster: &RelayRoster,
    guards: Option<&GuardSelector>,
    jurisdiction: &JurisdictionPolicy,
    policy: &RelayPruningPolicy,
    min_reputation: f64,
    max_attempts: usize,
) -> Result<Vec<RelayRecord>, TopologyError> {
    let path = select_diverse_reputation_path_pruned(
        topology,
        roster,
        guards,
        jurisdiction,
        policy,
        min_reputation,
        max_attempts,
    )?;
    relay_records_for_path(&path, roster)
}

/// Like [`select_diverse_reputation_path`] but also applies
/// [`RelayPruningPolicy::is_eligible`] on every hop.
pub fn select_diverse_reputation_path_pruned(
    topology: &Topology,
    roster: &RelayRoster,
    guards: Option<&GuardSelector>,
    jurisdiction: &JurisdictionPolicy,
    policy: &RelayPruningPolicy,
    min_reputation: f64,
    max_attempts: usize,
) -> Result<Vec<RelayId>, TopologyError> {
    for _ in 0..max_attempts {
        let path = select_path_indexed_impl(topology, guards, 0)?;
        if !path_satisfies_pruning_policy(&path, policy, min_reputation) {
            continue;
        }
        if path_satisfies_jurisdiction(&path, roster, jurisdiction)? {
            return Ok(path);
        }
    }
    Err(TopologyError::ReputationPathExhausted {
        attempts: max_attempts,
    })
}

#[cfg(test)]
mod tests {
    use aegis_trust::policy::{RelayPruningPolicy, DEFAULT_PATH_REPUTATION_FLOOR};
    use aegis_trust::reputation::ReputationLedger;

    use super::*;
    use crate::layers::build_topology;
    use crate::types::{test_relay_id, test_relay_record, RelayId, TopologyConfig};

    fn sample_roster(n: u64, jurisdictions: &[&str]) -> RelayRoster {
        let mut roster = RelayRoster::new();
        for i in 0..n {
            let j = jurisdictions[i as usize % jurisdictions.len()];
            roster.admit_for_tests(test_relay_record(i + 1, j));
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
        let bad = test_relay_id(1);
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
    #[allow(deprecated)]
    fn reputation_unaware_path_selection_unchanged() {
        let roster = sample_roster(24, &["US", "DE", "FR", "UK", "JP", "CA"]);
        let topo = build_topology(&roster, 1, &TopologyConfig::high_threat(), 0).unwrap();
        let path = select_path(&topo, None).unwrap();
        assert_eq!(path.len(), 4);
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
    fn pruned_path_excludes_anomaly_demoted_relay() {
        let roster = sample_roster(24, &["US", "DE", "FR", "UK", "JP", "CA"]);
        let topo = build_topology(&roster, 1, &TopologyConfig::high_threat(), 0).unwrap();
        let bad = test_relay_id(1);
        let policy = demote_via_anomaly(bad);

        for _ in 0..200 {
            let path = select_path_reputation_weighted_pruned(
                &topo,
                &roster,
                None,
                &policy,
                DEFAULT_PATH_REPUTATION_FLOOR,
                50,
            )
            .unwrap();
            assert!(
                !path.contains(&bad),
                "demoted relay must never appear on pruned path"
            );
        }
    }

    #[test]
    fn build_bound_path_pruned_excludes_demoted_and_returns_commitments() {
        let roster = sample_roster(24, &["US", "DE", "FR", "UK", "JP", "CA"]);
        let topo = build_topology(&roster, 1, &TopologyConfig::high_threat(), 0).unwrap();
        let bad = test_relay_id(1);
        let policy = demote_via_anomaly(bad);

        for _ in 0..200 {
            let records = build_bound_path_pruned(
                &topo,
                &roster,
                None,
                &policy,
                DEFAULT_PATH_REPUTATION_FLOOR,
                50,
            )
            .unwrap();
            assert_eq!(records.len(), topo.layer_count);
            assert!(
                !records.iter().any(|r| r.id == bad),
                "demoted relay must never appear on bound path"
            );
            for record in &records {
                assert_eq!(
                    record.kem_public_commitment,
                    roster.get(record.id).unwrap().kem_public_commitment,
                    "bound path must carry roster KEM commitments"
                );
            }
        }
    }

    #[test]
    fn pruned_path_exhausts_when_only_demoted_relays_remain() {
        let mut roster = RelayRoster::new();
        let jurisdictions = ["US", "DE", "FR", "UK"];
        for i in 0..4 {
            roster.admit_for_tests(test_relay_record(i, jurisdictions[i as usize]));
        }
        let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();
        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for id in topo.layers.iter().flatten() {
            for _ in 0..100 {
                policy.observe_metric(*id.as_bytes(), 10.0);
            }
            policy.observe_metric(*id.as_bytes(), 1000.0);
            assert!(!policy.is_eligible(*id.as_bytes(), DEFAULT_PATH_REPUTATION_FLOOR));
        }

        let err = select_path_reputation_weighted_pruned(
            &topo,
            &roster,
            None,
            &policy,
            DEFAULT_PATH_REPUTATION_FLOOR,
            20,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TopologyError::ReputationPathExhausted { attempts: 20 }
        ));
    }
}
