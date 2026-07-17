//! Thin helpers wiring [`aegis_trust::policy::RelayPruningPolicy`] into path checks.
//!
//! Reputation filtering already lives in [`crate::path`]; this module adds the
//! anomaly-pruning eligibility hook without touching roster/admission types.

use aegis_trust::policy::RelayPruningPolicy;

use crate::types::RelayId;

/// Returns `true` when `relay` passes [`RelayPruningPolicy::is_eligible`] at
/// `min_reputation`.
pub fn relay_satisfies_pruning_policy(
    relay: RelayId,
    policy: &RelayPruningPolicy,
    min_reputation: f64,
) -> bool {
    policy.is_eligible(*relay.as_bytes(), min_reputation)
}

/// Returns `true` when every hop on `path` passes [`RelayPruningPolicy::is_eligible`].
pub fn path_satisfies_pruning_policy(
    path: &[RelayId],
    policy: &RelayPruningPolicy,
    min_reputation: f64,
) -> bool {
    path
        .iter()
        .all(|id| relay_satisfies_pruning_policy(*id, policy, min_reputation))
}

#[cfg(test)]
mod tests {
    use aegis_trust::policy::{RelayPruningPolicy, DEFAULT_PATH_REPUTATION_FLOOR};

    use crate::guards::{GuardConfig, GuardSelector};
    use crate::layers::build_topology;
    use crate::path::select_path_reputation_weighted_pruned;
    use crate::types::{test_relay_record, RelayId, TopologyConfig};

    fn sample_roster(n: u64) -> crate::roster::RelayRoster {
        let mut roster = crate::roster::RelayRoster::new();
        for i in 0..n {
            roster.admit(test_relay_record(i + 1, "US"));
        }
        roster
    }

    #[test]
    fn pruned_selection_excludes_anomaly_demoted_relay_end_to_end() {
        let roster = sample_roster(24);
        let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();
        let target = RelayId::from_u64(1);

        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for _ in 0..100 {
            policy.observe_metric(*target.as_bytes(), 10.0);
        }
        policy.observe_metric(*target.as_bytes(), 1000.0);
        assert!(!policy.is_eligible(*target.as_bytes(), DEFAULT_PATH_REPUTATION_FLOOR));

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
                !path.contains(&target),
                "demoted relay must never appear on pruned path"
            );
        }

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
                !guards.guards.contains(&target),
                "demoted relay must never be selected as guard"
            );
        }
    }
}
