//! Sybil admission attack against the REAL roster + guard/path selection code.
//!
//! Simulates an attacker who controls the consortium admission-signing key
//! (`ConsortiumKey`) and floods signed Sybil relays via `RelayRoster::admit_signed`.
//! Measures what fraction of the guard and path-selection surface Sybils capture
//! under the actual `build_topology` / `GuardSelector` / `select_path*` logic.
//!
//! Run: `cargo test -p aegis-topology --test sybil_admission`

use std::collections::HashSet;
use std::time::Duration;

use aegis_topology::guards::{guard_exposure_plateau, GuardConfig, GuardSelector};
use aegis_topology::path::{select_path, select_path_reputation_weighted};
use aegis_topology::roster::{ConsortiumKey, RelayRoster, RosterAdmissionPolicy};
use aegis_topology::types::{test_relay_record, RelayId, RelayRecord, TopologyConfig};
use aegis_topology::build_topology;
use aegis_trust::reputation::{ReputationLedger, ReputationScore};
use rand::rngs::OsRng;

const HONEST_COUNT: u64 = 24;
const JURISDICTIONS: &[&str] = &["US", "DE", "FR", "UK", "JP", "CA"];
const CLIENT_SEEDS: u64 = 2_000;
const PATH_TRIALS: usize = 2_000;
const MIN_REPUTATION: f64 = 0.3;

/// Baseline (pre-fix) empirical numbers from the same scenarios, before probation +
/// rate limiting — documented for before/after comparison in the threat model.
mod baseline_pre_fix {
    pub const FLOOD_50_REP_PATH_SYBIL: f64 = 0.45; // >0.4 asserted; fresh NEUTRAL passed floor
    pub const _FLOOD_50_PRIMARY_GUARD_SYBIL: f64 = 0.50; // tracks ~50% layer-1 share
    pub const _FLOOD_80_PRIMARY_GUARD_SYBIL: f64 = 0.60;
}

fn honest_record(id: u64) -> RelayRecord {
    test_relay_record(
        id,
        JURISDICTIONS[id as usize % JURISDICTIONS.len() as usize],
    )
}

fn sybil_record(id: u64) -> RelayRecord {
    test_relay_record(id, "SY")
}

/// Permissive policy for scenarios that admit a large honest+sybil batch in one run.
fn build_mixed_roster(
    sybil_count: u64,
    authority: &ConsortiumKey,
) -> (RelayRoster, HashSet<RelayId>, ReputationLedger) {
    let mut roster =
        RelayRoster::with_admission_policy(RosterAdmissionPolicy::permissive_for_tests());
    let pk = authority.verifying_key();
    let mut sybil_ids = HashSet::new();
    let mut ledger = ReputationLedger::new(0.9).expect("ledger");

    for id in 1..=HONEST_COUNT {
        let signed = authority.sign_record(&honest_record(id));
        roster
            .admit_signed(signed, &pk, &mut ledger)
            .expect("honest admit");
        seed_vetted_reputation(&mut ledger, RelayId::from_u64(id));
    }

    for i in 0..sybil_count {
        let id = 10_000 + i;
        let signed = authority.sign_record(&sybil_record(id));
        roster
            .admit_signed(signed, &pk, &mut ledger)
            .expect("sybil admit");
        sybil_ids.insert(RelayId::from_u64(id));
        assert_eq!(
            ledger.score(*RelayId::from_u64(id).as_bytes()).0,
            ReputationScore::PROBATIONARY.0
        );
    }

    (roster, sybil_ids, ledger)
}

/// Vetted honest relays earn reputation above the 0.3 path/guard floor.
fn seed_vetted_reputation(ledger: &mut ReputationLedger, id: RelayId) {
    for _ in 0..30 {
        ledger.record_success(*id.as_bytes());
    }
    assert!(ledger.score(*id.as_bytes()).0 >= MIN_REPUTATION);
}

struct ExposureMetrics {
    layer1_sybil_fraction: f64,
    primary_guard_sybil_rate: f64,
    path_any_sybil_rate: f64,
    path_any_sybil_reputation_filtered: f64,
    primary_expected: f64,
}

fn measure_exposure(
    roster: &RelayRoster,
    sybil_ids: &HashSet<RelayId>,
    ledger: &ReputationLedger,
) -> ExposureMetrics {
    let topo = build_topology(roster, 7, &TopologyConfig::high_threat(), 99).expect("topology");
    let layer1 = topo.layer(0).expect("layer 1");
    let layer1_sybil = layer1.iter().filter(|id| sybil_ids.contains(id)).count();
    let layer1_sybil_fraction = layer1_sybil as f64 / layer1.len() as f64;

    let guard_config = GuardConfig::default();
    let mut primary_hits = 0u64;
    for seed in 0..CLIENT_SEEDS {
        let guards = GuardSelector::new(&topo, &guard_config, seed).expect("guards");
        if sybil_ids.contains(&guards.primary_guard()) {
            primary_hits += 1;
        }
    }
    let primary_guard_sybil_rate = primary_hits as f64 / CLIENT_SEEDS as f64;

    let mut path_hits = 0usize;
    for _ in 0..PATH_TRIALS {
        let path = select_path(&topo, None).expect("path");
        if path.iter().any(|id| sybil_ids.contains(id)) {
            path_hits += 1;
        }
    }
    let path_any_sybil_rate = path_hits as f64 / PATH_TRIALS as f64;

    let mut rep_hits = 0usize;
    for _ in 0..PATH_TRIALS {
        if let Ok(path) = select_path_reputation_weighted(
            &topo,
            roster,
            None,
            ledger,
            MIN_REPUTATION,
            50,
        ) {
            if path.iter().any(|id| sybil_ids.contains(id)) {
                rep_hits += 1;
            }
        }
    }
    let path_any_sybil_reputation_filtered = rep_hits as f64 / PATH_TRIALS as f64;

    let primary_expected = layer1_sybil_fraction;

    ExposureMetrics {
        layer1_sybil_fraction,
        primary_guard_sybil_rate,
        path_any_sybil_rate,
        path_any_sybil_reputation_filtered,
        primary_expected,
    }
}

#[test]
fn sybil_flood_reputation_filter_blocks_probationary_sybils() {
    let mut rng = OsRng;
    let authority = ConsortiumKey::generate(&mut rng);

    let (honest_roster, empty, ledger) = build_mixed_roster(0, &authority);
    let baseline = measure_exposure(&honest_roster, &empty, &ledger);
    assert!(
        baseline.primary_guard_sybil_rate < 0.01,
        "baseline guard sybil rate should be ~0, got {}",
        baseline.primary_guard_sybil_rate
    );

    let paper_plateau = guard_exposure_plateau(0.01, GuardConfig::default().guard_count);
    assert!(
        (paper_plateau - 0.03).abs() < 0.005,
        "paper control plateau ~3%: {paper_plateau}"
    );

    let (mixed_roster, sybil_ids, ledger) = build_mixed_roster(24, &authority);
    assert_eq!(mixed_roster.len(), 48);
    let half = measure_exposure(&mixed_roster, &sybil_ids, &ledger);

    eprintln!(
        "50% flood post-fix: layer1_sybil={:.3} primary_guard={:.3} path={:.3} rep_filtered={:.3} (baseline rep_filtered ~{:.2})",
        half.layer1_sybil_fraction,
        half.primary_guard_sybil_rate,
        half.path_any_sybil_rate,
        half.path_any_sybil_reputation_filtered,
        baseline_pre_fix::FLOOD_50_REP_PATH_SYBIL
    );

    assert!(
        half.layer1_sybil_fraction > 0.35,
        "layer1 sybil fraction should rise with 50% flood: {}",
        half.layer1_sybil_fraction
    );

    // Unguarded selection still captures ~layer-1 Sybil share (topology unchanged).
    assert!(
        (half.primary_guard_sybil_rate - half.primary_expected).abs() < 0.08,
        "empirical primary guard rate {} should track layer1 fraction {}",
        half.primary_guard_sybil_rate,
        half.primary_expected
    );
    assert!(
        half.primary_guard_sybil_rate > paper_plateau * 5.0,
        "50% Sybil flood ({}) should far exceed paper ~3% plateau ({paper_plateau})",
        half.primary_guard_sybil_rate
    );

    // Post-fix: probationary Sybils (0.1) are below the 0.3 floor — reputation filter bites.
    assert!(
        half.path_any_sybil_reputation_filtered
            < baseline_pre_fix::FLOOD_50_REP_PATH_SYBIL * 0.25,
        "reputation filter should block most fresh Sybils: {:.3} vs pre-fix ~{:.2}",
        half.path_any_sybil_reputation_filtered,
        baseline_pre_fix::FLOOD_50_REP_PATH_SYBIL
    );
    assert!(
        half.path_any_sybil_reputation_filtered < half.path_any_sybil_rate * 0.15,
        "reputation filter should meaningfully cut path exposure: {:.3} vs unfiltered {:.3}",
        half.path_any_sybil_reputation_filtered,
        half.path_any_sybil_rate
    );
}

#[test]
fn sybil_majority_flood_approaches_saturation_without_reputation_guard() {
    let mut rng = OsRng;
    let authority = ConsortiumKey::generate(&mut rng);
    let (roster, sybil_ids, ledger) = build_mixed_roster(96, &authority);
    let m = measure_exposure(&roster, &sybil_ids, &ledger);

    eprintln!(
        "80% flood post-fix: layer1_sybil={:.3} primary_guard={:.3} path={:.3} rep_filtered={:.3}",
        m.layer1_sybil_fraction,
        m.primary_guard_sybil_rate,
        m.path_any_sybil_rate,
        m.path_any_sybil_reputation_filtered
    );

    assert!(m.layer1_sybil_fraction > 0.55, "layer1 dominated: {}", m.layer1_sybil_fraction);
    assert!(
        m.primary_guard_sybil_rate > 0.55,
        "guard capture should be high: {}",
        m.primary_guard_sybil_rate
    );
    assert!(
        (m.primary_guard_sybil_rate - m.primary_expected).abs() < 0.08,
        "empirical {} vs expected {}",
        m.primary_guard_sybil_rate,
        m.primary_expected
    );
    assert!(
        m.path_any_sybil_rate > 0.90,
        "path capture should saturate: {}",
        m.path_any_sybil_rate
    );
    assert!(
        m.path_any_sybil_reputation_filtered < 0.05,
        "probationary Sybils should not pass reputation-filtered paths: {}",
        m.path_any_sybil_reputation_filtered
    );
}

#[test]
fn vetted_one_percent_roster_matches_paper_plateau_assumption() {
    let mut rng = OsRng;
    let authority = ConsortiumKey::generate(&mut rng);
    let pk = authority.verifying_key();
    let mut ledger = ReputationLedger::new(0.9).unwrap();

    let mut roster =
        RelayRoster::with_admission_policy(RosterAdmissionPolicy::permissive_for_tests());
    let sybil_id = RelayId::from_u64(10_000);
    for id in 1..=99 {
        roster
            .admit_signed(authority.sign_record(&honest_record(id)), &pk, &mut ledger)
            .unwrap();
        seed_vetted_reputation(&mut ledger, RelayId::from_u64(id));
    }
    roster
        .admit_signed(authority.sign_record(&sybil_record(10_000)), &pk, &mut ledger)
        .unwrap();

    let sybil_ids = HashSet::from([sybil_id]);
    let m = measure_exposure(&roster, &sybil_ids, &ledger);

    let paper = guard_exposure_plateau(0.01, 3);
    assert!(
        (m.layer1_sybil_fraction - 0.01).abs() < 0.05,
        "layer1 c≈1%: {}",
        m.layer1_sybil_fraction
    );
    assert!(
        (m.primary_guard_sybil_rate - m.layer1_sybil_fraction).abs() < 0.04,
        "primary guard rate {} ≈ layer1 c {}",
        m.primary_guard_sybil_rate,
        m.layer1_sybil_fraction
    );
    assert!(
        m.primary_guard_sybil_rate < paper,
        "single-primary exposure ({}) is below g=3 paper plateau ({paper}) at c=1%",
        m.primary_guard_sybil_rate
    );
    assert!(
        m.path_any_sybil_reputation_filtered < 0.02,
        "one probationary Sybil should not drive reputation-filtered paths: {}",
        m.path_any_sybil_reputation_filtered
    );
}

#[test]
fn reputation_weighted_guard_excludes_probationary_and_sub_floor_sybils() {
    let mut rng = OsRng;
    let authority = ConsortiumKey::generate(&mut rng);
    let (roster, sybil_ids, mut ledger) = build_mixed_roster(12, &authority);
    let topo = build_topology(&roster, 0, &TopologyConfig::high_threat(), 0).unwrap();

    let bad_sybil = *sybil_ids.iter().next().expect("sybil");
    for _ in 0..30 {
        ledger.record_failure(*bad_sybil.as_bytes());
    }
    assert!(ledger.score(*bad_sybil.as_bytes()).0 < MIN_REPUTATION);

    let guard_config = GuardConfig::default();
    for seed in 0..200u64 {
        let guards = GuardSelector::new_reputation_weighted(
            &topo,
            &guard_config,
            seed,
            &ledger,
            MIN_REPUTATION,
        )
        .expect("rep guards");
        assert!(!guards.guards.contains(&bad_sybil));
    }

    // Fresh probationary Sybils are also excluded from reputation-weighted guards.
    let fresh: Vec<_> = sybil_ids
        .iter()
        .filter(|id| **id != bad_sybil)
        .collect();
    assert!(!fresh.is_empty());
    for seed in 0..200u64 {
        let guards = GuardSelector::new_reputation_weighted(
            &topo,
            &guard_config,
            seed,
            &ledger,
            MIN_REPUTATION,
        )
        .expect("rep guards");
        for id in &fresh {
            assert!(!guards.guards.contains(id));
        }
    }
}

#[test]
fn admission_rate_limit_caps_sybil_roster_growth_per_window() {
    let mut rng = OsRng;
    let authority = ConsortiumKey::generate(&mut rng);
    let pk = authority.verifying_key();

    let policy = RosterAdmissionPolicy {
        max_admissions_per_window: 5,
        window: Duration::from_secs(24 * 60 * 60),
    };
    let mut roster = RelayRoster::with_admission_policy(policy);
    let mut ledger = ReputationLedger::new(0.9).unwrap();

    // Long-standing vetted pool (pre-window, test-only admit — unseen => NEUTRAL for compat).
    for id in 1..=HONEST_COUNT {
        roster.admit_for_tests(honest_record(id));
        seed_vetted_reputation(&mut ledger, RelayId::from_u64(id));
    }

    let mut admitted_sybils = 0u64;
    for i in 0..500 {
        let signed = authority.sign_record(&sybil_record(20_000 + i));
        match roster.admit_signed(signed, &pk, &mut ledger) {
            Ok(()) => admitted_sybils += 1,
            Err(aegis_topology::RosterError::AdmissionRateLimitExceeded { .. }) => break,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(
        admitted_sybils, 5,
        "default policy should cap attacker to 5 Sybil admits per 24h window"
    );
    assert_eq!(
        roster.len(),
        HONEST_COUNT as usize + 5,
        "roster growth bounded by rate limit"
    );

    // With only 5 Sybils vs 24 honest, capture should stay well below pre-fix 50% flood.
    let sybil_ids: HashSet<_> = (0..admitted_sybils)
        .map(|i| RelayId::from_u64(20_000 + i))
        .collect();
    let m = measure_exposure(&roster, &sybil_ids, &ledger);
    eprintln!(
        "rate-limited flood: layer1_sybil={:.3} primary_guard={:.3} rep_filtered={:.3} (pre-fix 50% rep_filtered ~{:.2})",
        m.layer1_sybil_fraction,
        m.primary_guard_sybil_rate,
        m.path_any_sybil_reputation_filtered,
        baseline_pre_fix::FLOOD_50_REP_PATH_SYBIL
    );

    assert!(m.layer1_sybil_fraction < 0.25, "only 5 Sybils admitted: {}", m.layer1_sybil_fraction);
    assert!(
        m.primary_guard_sybil_rate < 0.25,
        "guard exposure capped by rate limit: {}",
        m.primary_guard_sybil_rate
    );
    assert!(
        m.path_any_sybil_reputation_filtered < 0.05,
        "probationary + sparse Sybils: {}",
        m.path_any_sybil_reputation_filtered
    );
}
