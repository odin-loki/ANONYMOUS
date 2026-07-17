//! # aegis-topology — Phase 3 + Phase 5 (guards/beacon/admission)
//!
//! Stratified L-tier topology, stable per-epoch membership, and **fresh CSPRNG-random**
//! per-packet path selection (never deterministic). Default L=4 high-threat;
//! full-path compromise = f^L. Also carries the Phase 5 pieces that are topology-
//! adjacent: stable/vetted/layered guards ([`guards`]), permissioned admission
//! ([`roster`]), and a public-randomness beacon for cover scheduling + committee
//! assignment ([`beacon`] — see that module's docs for its honest scope limits).
//!
//! See `docs/AEGIS_SPEC_v3_consolidated.md` §4.5, §4.6, §4.7, §7 and the Phase gates in §10.

pub mod beacon;
pub mod error;
pub mod guards;
pub mod layers;
pub mod path;
pub mod pruning;
pub mod roster;
pub mod types;

pub use beacon::{
    committee_for_round, round_at, Beacon, BeaconError, BeaconParticipant, HashChainBeacon,
    ThresholdBeacon, ThresholdBeaconCommittee,
};
pub use error::{RosterError, TopologyError};
pub use guards::{guard_exposure_plateau, GuardConfig, GuardSelector};
pub use layers::{build_topology, build_topology_reputation_filtered, Topology};
pub use path::{
    build_bound_path_diverse_pruned, build_bound_path_pruned, path_compromise_probability,
    path_satisfies_jurisdiction, path_satisfies_reputation, relay_records_for_path,
    select_diverse_path, select_diverse_reputation_path, select_diverse_reputation_path_pruned,
    select_path, select_path_reputation_weighted, select_path_reputation_weighted_pruned,
    JurisdictionPolicy,
};
pub use pruning::{
    path_satisfies_pruning_policy, relay_admission_satisfies_pruning_policy,
    relay_satisfies_pruning_policy,
};
pub use roster::{
    AuthorityAdmissionSignature, ConsortiumKey, RelayRoster, RosterAdmissionPolicy,
    SignedRelayRecord, ThresholdConsortium, ThresholdSignedRelayRecord,
};
pub use types::{
    test_kem_public_for_id, test_relay_record, JurisdictionId, KemPublicCommitment, RelayId,
    RelayRecord, TopologyConfig,
};

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;

    fn sample_roster(n: u64, jurisdictions: &[&str]) -> RelayRoster {
        let mut roster = RelayRoster::new();
        for i in 0..n {
            let j = jurisdictions[i as usize % jurisdictions.len()];
            roster.admit(test_relay_record(i + 1, j));
        }
        roster
    }

    #[test]
    fn layer_assignment_produces_l_layers_with_even_sizes() {
        let roster = sample_roster(24, &["US", "DE", "FR", "UK", "JP", "CA"]);
        let config = TopologyConfig::high_threat();
        let topo = build_topology(&roster, 42, &config, 99).expect("build");

        assert_eq!(topo.layer_count, 4);
        assert_eq!(topo.layers.len(), 4);
        for layer in &topo.layers {
            assert_eq!(layer.len(), 6, "24 relays / L=4 => 6 per layer");
        }

        let all: HashSet<_> = topo.layers.iter().flatten().copied().collect();
        assert_eq!(all.len(), 24);
    }

    #[test]
    fn epoch_membership_is_stable_for_same_epoch() {
        let roster = sample_roster(12, &["US", "DE"]);
        let config = TopologyConfig::standard();
        let a = build_topology(&roster, 7, &config, 1).unwrap();
        let b = build_topology(&roster, 7, &config, 1).unwrap();
        assert_eq!(a.layers, b.layers);

        let c = build_topology(&roster, 8, &config, 1).unwrap();
        assert_ne!(a.layers, c.layers, "different epoch should reshuffle");
    }

    #[test]
    fn path_selection_one_per_layer_and_non_degenerate() {
        let roster = sample_roster(24, &["US", "DE", "FR", "UK", "JP", "CA"]);
        let topo = build_topology(&roster, 1, &TopologyConfig::high_threat(), 0).unwrap();

        const N: usize = 500;
        let mut full_paths: HashSet<Vec<RelayId>> = HashSet::new();
        let mut layer1_counts: HashMap<RelayId, usize> = HashMap::new();

        for _ in 0..N {
            let path = select_path(&topo, None).unwrap();
            assert_eq!(path.len(), 4);
            for (layer_idx, relay) in path.iter().enumerate() {
                assert!(
                    topo.layers[layer_idx].contains(relay),
                    "relay must belong to its layer"
                );
            }
            full_paths.insert(path.clone());
            *layer1_counts.entry(path[0]).or_insert(0) += 1;
        }

        assert!(
            full_paths.len() >= 20,
            "expected diverse full paths, got {}",
            full_paths.len()
        );

        let max_layer1 = layer1_counts.values().copied().max().unwrap_or(0);
        assert!(
            max_layer1 < N * 60 / 100,
            "no single layer-1 relay should dominate (>60%): max={max_layer1}/{N}"
        );
    }

    #[test]
    fn path_selection_with_stable_guard_fixes_layer_one() {
        let roster = sample_roster(24, &["US", "DE", "FR", "UK", "JP", "CA"]);
        let topo = build_topology(&roster, 5, &TopologyConfig::high_threat(), 0).unwrap();
        let guards = GuardSelector::new(&topo, &GuardConfig::default(), 123).unwrap();
        let primary = guards.primary_guard();

        for _ in 0..50 {
            let path = select_path(&topo, Some(&guards)).unwrap();
            assert_eq!(path[0], primary, "layer 1 must be stable guard");
            assert_eq!(path.len(), 4);
        }
    }

    #[test]
    fn path_compromise_probability_at_thirty_percent_adversary() {
        let p = path_compromise_probability(0.3, 4);
        assert!(p < 0.01, "L=4 should keep full-path compromise <1% at f=30%: {p}");
        assert!((p - 0.0081).abs() < 1e-10);
    }

    #[test]
    fn guard_exposure_plateau_reproduces_evidence_ledger() {
        let g = GuardConfig::default().guard_count;

        let high = guard_exposure_plateau(0.10, g);
        assert!(
            (high - 0.27).abs() < 0.02,
            "c=10% plateau ~27% with g={g}: got {high}"
        );

        let low = guard_exposure_plateau(0.01, g);
        assert!(
            (low - 0.03).abs() < 0.01,
            "c=1% plateau ~3% with g={g}: got {low}"
        );
    }

    #[test]
    fn jurisdiction_check_rejects_concentrated_path() {
        let mut roster = RelayRoster::new();
        for i in 0..4 {
            roster.admit(test_relay_record(i, "US"));
        }
        let path: Vec<_> = (0..4).map(RelayId::from_u64).collect();
        let policy = JurisdictionPolicy::default();

        let ok = path_satisfies_jurisdiction(&path, &roster, &policy).unwrap();
        assert!(!ok, "all-US path should fail max_per_jurisdiction=1");
    }

    #[test]
    fn jurisdiction_check_passes_diverse_path() {
        let mut roster = RelayRoster::new();
        let jurisdictions = ["US", "DE", "FR", "UK"];
        for (i, j) in jurisdictions.iter().enumerate() {
            roster.admit(test_relay_record(i as u64, *j));
        }
        let path: Vec<_> = (0..4).map(RelayId::from_u64).collect();
        let policy = JurisdictionPolicy::default();

        let ok = path_satisfies_jurisdiction(&path, &roster, &policy).unwrap();
        assert!(ok);
    }

    #[test]
    fn admission_roster_controls_eligibility() {
        let roster = sample_roster(8, &["US", "DE", "FR", "UK"]);
        let admitted_id = roster.admitted_sorted()[0].id;
        assert!(roster.is_admitted(admitted_id));

        let mut pruned = roster.clone();
        assert!(pruned.remove(admitted_id));
        assert!(!pruned.is_admitted(admitted_id));

        let topo = build_topology(&pruned, 0, &TopologyConfig::high_threat(), 0).unwrap();
        for layer in &topo.layers {
            for id in layer {
                assert!(!pruned.is_admitted(*id) || *id != admitted_id);
            }
        }
        assert!(!topo.layers.iter().flatten().any(|id| *id == admitted_id));

        let path = select_path(&topo, None).unwrap();
        for id in &path {
            assert!(pruned.is_admitted(*id));
        }
    }

    #[test]
    fn empty_roster_rejected() {
        let roster = RelayRoster::new();
        let err = build_topology(&roster, 0, &TopologyConfig::default(), 0).unwrap_err();
        assert_eq!(err, TopologyError::EmptyRoster);
    }

    #[test]
    fn guard_selector_requires_enough_layer_one_relays() {
        let roster = sample_roster(2, &["US", "DE"]);
        let topo = build_topology(&roster, 0, &TopologyConfig::standard(), 0).unwrap();
        let err = GuardSelector::new(&topo, &GuardConfig::default(), 0).unwrap_err();
        assert!(matches!(
            err,
            TopologyError::InsufficientGuards { needed: 3, .. }
        ));
    }
}
