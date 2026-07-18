//! Reputation-weighted bound path construction with guard mitigation.

use aegis_topology::layers::Topology;
use aegis_topology::path::{
    build_bound_path_diverse_pruned_with_guards_mitigated,
    build_bound_path_pruned_with_guards_mitigated,
};
use aegis_topology::{
    GuardConfig, GuardMitigationPolicy, GuardMitigationSignals, GuardSelector, JurisdictionPolicy,
    RelayRoster, TopologyError,
};
use aegis_trust::policy::RelayPruningPolicy;
use aegis_topology::types::RelayRecord;

/// Parameters for client-side bound path + guard selection.
#[derive(Clone, Debug)]
pub struct ClientPathBuildParams {
    /// Base client seed for guard-set sampling (re-mixed when mitigation re-samples).
    pub client_seed: u64,
    /// Base guard config before mitigation pin-mode adjustment.
    pub guard_config: GuardConfig,
    /// Mitigation policy (typically from `[guard_mitigation]` TOML).
    pub mitigation: GuardMitigationPolicy,
    /// Epoch/anomaly signals; use [`GuardMitigationSignals::default()`] when unavailable.
    pub signals: GuardMitigationSignals,
    pub min_reputation: f64,
    pub max_attempts: usize,
    /// When `Some`, enforce jurisdiction diversity after mitigation (opt-in).
    pub jurisdiction: Option<JurisdictionPolicy>,
}

impl Default for ClientPathBuildParams {
    fn default() -> Self {
        Self {
            client_seed: 0,
            guard_config: GuardConfig::default(),
            mitigation: GuardMitigationPolicy::disabled(),
            signals: GuardMitigationSignals::default(),
            min_reputation: aegis_trust::policy::DEFAULT_PATH_REPUTATION_FLOOR,
            max_attempts: 50,
            jurisdiction: None,
        }
    }
}

/// Build a pruned bound path and reputation-weighted guard set with mitigation applied.
///
/// This is the production entry point for roster-driven client paths (not explicit hop lists).
/// When [`ClientPathBuildParams::jurisdiction`] is set, composes adaptive mitigation with
/// [`build_bound_path_diverse_pruned_with_guards_mitigated`].
pub fn build_client_bound_path(
    topology: &Topology,
    roster: &RelayRoster,
    pruning: &RelayPruningPolicy,
    params: &ClientPathBuildParams,
) -> Result<(GuardSelector, Vec<RelayRecord>), TopologyError> {
    if let Some(ref jurisdiction) = params.jurisdiction {
        build_bound_path_diverse_pruned_with_guards_mitigated(
            topology,
            roster,
            &params.guard_config,
            params.client_seed,
            &params.mitigation,
            &params.signals,
            jurisdiction,
            pruning,
            params.min_reputation,
            params.max_attempts,
        )
    } else {
        build_bound_path_pruned_with_guards_mitigated(
            topology,
            roster,
            &params.guard_config,
            params.client_seed,
            &params.mitigation,
            &params.signals,
            pruning,
            params.min_reputation,
            params.max_attempts,
        )
    }
}

#[cfg(test)]
mod tests {
    use aegis_topology::layers::build_topology;
    use aegis_topology::path::path_satisfies_jurisdiction;
    use aegis_topology::types::{test_relay_record, TopologyConfig};
    use aegis_topology::{GuardPinMode, GUARD_SET_SIZE};

    use super::*;

    fn sample_roster(n: u64) -> aegis_topology::RelayRoster {
        let mut roster = aegis_topology::RelayRoster::new();
        for i in 0..n {
            roster.admit_for_tests(test_relay_record(i + 1, "US"));
        }
        roster
    }

    fn diverse_roster(n: u64) -> aegis_topology::RelayRoster {
        let jurisdictions = ["US", "DE", "FR", "UK", "JP", "CA", "AU", "SE"];
        let mut roster = aegis_topology::RelayRoster::new();
        for i in 0..n {
            let j = jurisdictions[i as usize % jurisdictions.len()];
            roster.admit_for_tests(test_relay_record(i + 1, j));
        }
        roster
    }

    #[test]
    fn adaptive_first_rotates_pin_on_anomaly_signal() {
        let roster = sample_roster(24);
        let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();
        let pruning = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        let params = ClientPathBuildParams {
            client_seed: 99,
            mitigation: GuardMitigationPolicy::adaptive_first(),
            signals: GuardMitigationSignals {
                anomaly_demotion_flag: true,
                ..GuardMitigationSignals::default()
            },
            ..ClientPathBuildParams::default()
        };
        let (guards, records) =
            build_client_bound_path(&topo, &roster, &pruning, &params).unwrap();
        assert_eq!(guards.pin_mode, GuardPinMode::Rotate);
        assert_eq!(records.len(), topo.layer_count);
        assert_eq!(guards.guard_set().len(), GUARD_SET_SIZE as usize);
    }

    #[test]
    fn disabled_mitigation_matches_unmitigated_seed() {
        let roster = sample_roster(24);
        let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();
        let pruning = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        let seed = 12345u64;
        let params = ClientPathBuildParams {
            client_seed: seed,
            ..ClientPathBuildParams::default()
        };
        let (guards_a, _) =
            build_client_bound_path(&topo, &roster, &pruning, &params).unwrap();
        let (guards_b, _) = aegis_topology::path::build_bound_path_pruned_with_guards(
            &topo,
            &roster,
            seed,
            &pruning,
            params.min_reputation,
            params.max_attempts,
        )
        .unwrap();
        assert_eq!(guards_a.guard_set(), guards_b.guard_set());
        assert_eq!(guards_a.pin_mode, guards_b.pin_mode);
    }

    #[test]
    fn jurisdiction_diversity_rejects_mono_jurisdiction_roster() {
        let roster = sample_roster(24);
        let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();
        let pruning = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        let params = ClientPathBuildParams {
            jurisdiction: Some(JurisdictionPolicy::default()),
            max_attempts: 20,
            ..ClientPathBuildParams::default()
        };
        let err = build_client_bound_path(&topo, &roster, &pruning, &params).unwrap_err();
        assert!(matches!(
            err,
            TopologyError::ReputationPathExhausted { attempts: 20 }
        ));
    }

    #[test]
    fn adaptive_v4_composes_with_jurisdiction_diversity() {
        let roster = diverse_roster(32);
        let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();
        let pruning = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        let jurisdiction = JurisdictionPolicy {
            max_per_jurisdiction: 1,
        };
        let params = ClientPathBuildParams {
            client_seed: 42,
            mitigation: GuardMitigationPolicy::adaptive_v4(),
            signals: GuardMitigationSignals {
                epoch_age: 2,
                anomaly_demotion_flag: true,
                ..GuardMitigationSignals::default()
            },
            jurisdiction: Some(jurisdiction),
            ..ClientPathBuildParams::default()
        };
        let (guards, records) =
            build_client_bound_path(&topo, &roster, &pruning, &params).unwrap();
        assert_eq!(guards.pin_mode, GuardPinMode::Rotate);
        assert_eq!(records.len(), topo.layer_count);
        let path: Vec<_> = records.iter().map(|r| r.id).collect();
        assert!(path_satisfies_jurisdiction(&path, &roster, &jurisdiction).unwrap());
    }
}
