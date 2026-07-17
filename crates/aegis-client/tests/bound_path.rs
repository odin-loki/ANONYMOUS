//! Pruned bound-path helper wired through client hop mapping.

use std::collections::HashMap;

use aegis_client::send::{build_packet_require_bindings, hops_from_bound_path};
use aegis_crypto::kem::RelayKemPublic;
use aegis_topology::layers::build_topology;
use aegis_topology::path::build_bound_path_pruned;
use aegis_topology::types::{
    test_kem_public_for_id, test_relay_id, test_relay_record, RelayId, TopologyConfig,
};
use aegis_trust::policy::{RelayPruningPolicy, DEFAULT_PATH_REPUTATION_FLOOR};
use rand_core::OsRng;

fn sample_roster(n: u64) -> (aegis_topology::RelayRoster, HashMap<RelayId, RelayKemPublic>) {
    let mut roster = aegis_topology::RelayRoster::new();
    let mut publics = HashMap::new();
    for i in 0..n {
        let fixture = i + 1;
        let record = test_relay_record(fixture, "US");
        publics.insert(record.id, test_kem_public_for_id(fixture));
        roster.admit_for_tests(record);
    }
    (roster, publics)
}

#[test]
fn bound_path_pruned_maps_to_require_bindings_hops() {
    let (roster, public_by_id) = sample_roster(24);
    let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();
    let target = test_relay_id(1);

    let mut policy = RelayPruningPolicy::new(0.9, 0.2, 3.0).unwrap();
    for _ in 0..100 {
        policy.observe_metric(*target.as_bytes(), 10.0);
    }
    policy.observe_metric(*target.as_bytes(), 1000.0);
    assert!(!policy.is_eligible(*target.as_bytes(), DEFAULT_PATH_REPUTATION_FLOOR));

    let mut rng = OsRng;
    for _ in 0..50 {
        let records = build_bound_path_pruned(
            &topo,
            &roster,
            None,
            &policy,
            DEFAULT_PATH_REPUTATION_FLOOR,
            50,
        )
        .unwrap();
        assert!(!records.iter().any(|r| r.id == target));

        let publics: Vec<_> = records
            .iter()
            .map(|r| public_by_id.get(&r.id).expect("fixture kem").clone())
            .collect();
        let hops = hops_from_bound_path(&records, &publics, &HashMap::new()).unwrap();
        assert!(build_packet_require_bindings(&hops, b"bound-pruned", &mut rng).is_ok());
    }
}
