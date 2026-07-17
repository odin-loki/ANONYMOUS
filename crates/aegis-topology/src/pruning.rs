//! Thin helpers wiring [`aegis_trust::policy::RelayPruningPolicy`] into path checks.
//!
//! Reputation filtering already lives in [`crate::path`]; this module adds the
//! anomaly-pruning eligibility hook without touching roster/admission types.

use aegis_trust::policy::RelayPruningPolicy;

use crate::types::RelayId;

/// Returns `true` when every hop on `path` passes [`RelayPruningPolicy::is_eligible`].
pub fn path_satisfies_pruning_policy(
    path: &[RelayId],
    policy: &RelayPruningPolicy,
    min_reputation: f64,
) -> bool {
    path.iter()
        .all(|id| policy.is_eligible(*id.as_bytes(), min_reputation))
}

#[cfg(test)]
mod tests {
    use aegis_trust::policy::{RelayPruningPolicy, DEFAULT_PATH_REPUTATION_FLOOR};

    use super::*;
    use crate::layers::build_topology;
    use crate::path::select_path;
    use crate::types::{test_relay_record, TopologyConfig};

    fn sample_roster(n: u64) -> crate::roster::RelayRoster {
        let mut roster = crate::roster::RelayRoster::new();
        for i in 0..n {
            roster.admit(test_relay_record(i + 1, "US"));
        }
        roster
    }

    #[test]
    fn pruned_relay_fails_path_eligibility_check() {
        let roster = sample_roster(24);
        let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();
        let target = RelayId::from_u64(1);

        let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
        for _ in 0..100 {
            policy.observe_metric(*target.as_bytes(), 10.0);
        }
        policy.observe_metric(*target.as_bytes(), 1000.0);

        let path = select_path(&topo, None).unwrap();
        if path.contains(&target) {
            assert!(
                !path_satisfies_pruning_policy(&path, &policy, DEFAULT_PATH_REPUTATION_FLOOR),
                "path containing demoted relay must fail pruning check"
            );
        }
    }
}
