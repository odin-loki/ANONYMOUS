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

use aegis_topology::guards::{
    guard_exposure_plateau, GuardConfig, GuardPinMode, GuardSelector, GUARD_SET_SIZE,
};
use aegis_topology::path::{select_path, select_path_reputation_weighted};
use aegis_topology::roster::{ConsortiumKey, RelayRoster, RosterAdmissionPolicy};
use aegis_topology::types::{test_relay_id, test_relay_record, RelayId, RelayRecord, TopologyConfig};
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
        seed_vetted_reputation(&mut ledger, test_relay_id(id));
    }

    for i in 0..sybil_count {
        let id = 10_000 + i;
        let signed = authority.sign_record(&sybil_record(id));
        roster
            .admit_signed(signed, &pk, &mut ledger)
            .expect("sybil admit");
        sybil_ids.insert(test_relay_id(id));
        assert_eq!(
            ledger.score(*test_relay_id(id).as_bytes()).0,
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
    /// Fraction of clients whose sticky primary is a Sybil (g=1 effective entry pin).
    primary_guard_sybil_rate: f64,
    /// Fraction of clients whose held g-set contains ≥1 Sybil (`1-(1-c)^g` empirical).
    guard_set_any_sybil_rate: f64,
    path_any_sybil_rate: f64,
    path_any_sybil_reputation_filtered: f64,
    /// Fraction of reputation-weighted g-sets that contain ≥1 Sybil.
    rep_guard_set_any_sybil_rate: f64,
    primary_expected: f64,
    set_expected: f64,
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
    assert_eq!(guard_config.guard_count, GUARD_SET_SIZE);

    let mut primary_hits = 0u64;
    let mut set_hits = 0u64;
    for seed in 0..CLIENT_SEEDS {
        let guards = GuardSelector::new(&topo, &guard_config, seed).expect("guards");
        assert_eq!(guards.guard_set().len(), GUARD_SET_SIZE as usize);
        if sybil_ids.contains(&guards.primary_guard()) {
            primary_hits += 1;
        }
        if guards.any_guard_compromised(sybil_ids) {
            set_hits += 1;
        }
    }
    let primary_guard_sybil_rate = primary_hits as f64 / CLIENT_SEEDS as f64;
    let guard_set_any_sybil_rate = set_hits as f64 / CLIENT_SEEDS as f64;

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

    let mut rep_set_hits = 0u64;
    let mut rep_set_ok = 0u64;
    for seed in 0..CLIENT_SEEDS {
        if let Ok(guards) = GuardSelector::new_reputation_weighted(
            &topo,
            &guard_config,
            seed,
            ledger,
            MIN_REPUTATION,
        ) {
            rep_set_ok += 1;
            if guards.any_guard_compromised(sybil_ids) {
                rep_set_hits += 1;
            }
        }
    }
    let rep_guard_set_any_sybil_rate = if rep_set_ok > 0 {
        rep_set_hits as f64 / rep_set_ok as f64
    } else {
        0.0
    };

    let primary_expected = layer1_sybil_fraction;
    let set_expected = guard_exposure_plateau(layer1_sybil_fraction, GUARD_SET_SIZE);

    ExposureMetrics {
        layer1_sybil_fraction,
        primary_guard_sybil_rate,
        guard_set_any_sybil_rate,
        path_any_sybil_rate,
        path_any_sybil_reputation_filtered,
        rep_guard_set_any_sybil_rate,
        primary_expected,
        set_expected,
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

    let paper_plateau = guard_exposure_plateau(0.01, GUARD_SET_SIZE);
    assert!(
        (paper_plateau - 0.03).abs() < 0.005,
        "paper control plateau ~3%: {paper_plateau}"
    );

    let (mixed_roster, sybil_ids, ledger) = build_mixed_roster(24, &authority);
    assert_eq!(mixed_roster.len(), 48);
    let half = measure_exposure(&mixed_roster, &sybil_ids, &ledger);

    eprintln!(
        "50% flood post-fix: layer1_sybil={:.3} primary_g1={:.3} set_g3={:.3} (expected {:.3}) \
         path={:.3} rep_path={:.3} rep_set_g3={:.3} (baseline rep_path ~{:.2})",
        half.layer1_sybil_fraction,
        half.primary_guard_sybil_rate,
        half.guard_set_any_sybil_rate,
        half.set_expected,
        half.path_any_sybil_rate,
        half.path_any_sybil_reputation_filtered,
        half.rep_guard_set_any_sybil_rate,
        baseline_pre_fix::FLOOD_50_REP_PATH_SYBIL
    );

    assert!(
        half.layer1_sybil_fraction > 0.35,
        "layer1 sybil fraction should rise with 50% flood: {}",
        half.layer1_sybil_fraction
    );

    // Sticky primary (g=1 pin) still tracks ~layer-1 Sybil share.
    assert!(
        (half.primary_guard_sybil_rate - half.primary_expected).abs() < 0.08,
        "empirical primary guard rate {} should track layer1 fraction {}",
        half.primary_guard_sybil_rate,
        half.primary_expected
    );
    assert!(
        half.primary_guard_sybil_rate > paper_plateau * 5.0,
        "50% Sybil flood primary ({}) should far exceed paper ~3% plateau ({paper_plateau})",
        half.primary_guard_sybil_rate
    );

    // Held g=3 set exposure tracks plateau formula (higher than primary, not saturation-only).
    assert!(
        (half.guard_set_any_sybil_rate - half.set_expected).abs() < 0.08,
        "g=3 set exposure {} should track 1-(1-c)^3 = {}",
        half.guard_set_any_sybil_rate,
        half.set_expected
    );
    assert!(
        half.guard_set_any_sybil_rate >= half.primary_guard_sybil_rate - 0.02,
        "set exposure should be ≥ primary: set={} primary={}",
        half.guard_set_any_sybil_rate,
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
    // g=3 + reputation: set capture collapses vs unfiltered g=1 primary.
    assert!(
        half.rep_guard_set_any_sybil_rate < 0.05,
        "reputation-weighted g=3 set should exclude probationary Sybils: {}",
        half.rep_guard_set_any_sybil_rate
    );
    assert!(
        half.rep_guard_set_any_sybil_rate < half.primary_guard_sybil_rate * 0.15,
        "g=3+rep plateau improvement vs unfiltered g=1 primary: rep_set={:.3} primary={:.3}",
        half.rep_guard_set_any_sybil_rate,
        half.primary_guard_sybil_rate
    );
}

/// Honest science: unfiltered sticky-primary (g=1 pin) still saturates under majority flood.
#[test]
fn sybil_majority_flood_unfiltered_g1_saturates() {
    let mut rng = OsRng;
    let authority = ConsortiumKey::generate(&mut rng);
    let (roster, sybil_ids, ledger) = build_mixed_roster(96, &authority);
    let m = measure_exposure(&roster, &sybil_ids, &ledger);

    eprintln!(
        "80% flood: layer1_sybil={:.3} primary_g1={:.3} set_g3={:.3} path={:.3} \
         rep_path={:.3} rep_set_g3={:.3}",
        m.layer1_sybil_fraction,
        m.primary_guard_sybil_rate,
        m.guard_set_any_sybil_rate,
        m.path_any_sybil_rate,
        m.path_any_sybil_reputation_filtered,
        m.rep_guard_set_any_sybil_rate
    );

    assert!(m.layer1_sybil_fraction > 0.55, "layer1 dominated: {}", m.layer1_sybil_fraction);
    assert!(
        m.primary_guard_sybil_rate > 0.55,
        "unfiltered g=1 primary capture should be high: {}",
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
        "unfiltered path capture should saturate: {}",
        m.path_any_sybil_rate
    );
    // Held g=3 without reputation also saturates when c is large (plateau → 1).
    assert!(
        m.guard_set_any_sybil_rate > 0.85,
        "unfiltered g=3 set also saturates at high c: {}",
        m.guard_set_any_sybil_rate
    );
    assert!(
        m.path_any_sybil_reputation_filtered < 0.05,
        "probationary Sybils should not pass reputation-filtered paths: {}",
        m.path_any_sybil_reputation_filtered
    );
    assert!(
        m.rep_guard_set_any_sybil_rate < 0.05,
        "g=3+rep still blocks fresh Sybils under majority flood: {}",
        m.rep_guard_set_any_sybil_rate
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
    let sybil_id = test_relay_id(10_000);
    for id in 1..=99 {
        roster
            .admit_signed(authority.sign_record(&honest_record(id)), &pk, &mut ledger)
            .unwrap();
        seed_vetted_reputation(&mut ledger, test_relay_id(id));
    }
    roster
        .admit_signed(authority.sign_record(&sybil_record(10_000)), &pk, &mut ledger)
        .unwrap();

    let sybil_ids = HashSet::from([sybil_id]);
    let m = measure_exposure(&roster, &sybil_ids, &ledger);

    // One Sybil among 100 → layer-1 share is 0 or 1/|L1| depending on epoch placement
    // (KEM-derived ids reshuffle strata vs legacy from_u64 fixtures).
    assert!(
        m.layer1_sybil_fraction <= 0.06,
        "layer1 Sybil share should be at most one relay in L1: {}",
        m.layer1_sybil_fraction
    );
    assert!(
        (m.primary_guard_sybil_rate - m.layer1_sybil_fraction).abs() < 0.04,
        "primary guard rate {} ≈ layer1 c {}",
        m.primary_guard_sybil_rate,
        m.layer1_sybil_fraction
    );
    // At small c, g=3 set exposure ≈ 1-(1-c)^3 ≈ 3c — the paper plateau.
    let paper = guard_exposure_plateau(m.layer1_sybil_fraction.max(0.01), GUARD_SET_SIZE);
    assert!(
        (m.guard_set_any_sybil_rate - m.set_expected).abs() < 0.05
            || m.layer1_sybil_fraction < 0.001,
        "g=3 set exposure {} should track plateau {} at c={}",
        m.guard_set_any_sybil_rate,
        m.set_expected,
        m.layer1_sybil_fraction
    );
    assert!(
        m.primary_guard_sybil_rate <= paper + 0.02,
        "sticky primary ({}) stays ≤ paper plateau ({paper}) at measured c={}",
        m.primary_guard_sybil_rate,
        m.layer1_sybil_fraction
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
        assert_eq!(guards.guard_set().len(), GUARD_SET_SIZE as usize);
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
fn rotate_pin_uses_full_guard_set() {
    let mut rng = OsRng;
    let authority = ConsortiumKey::generate(&mut rng);
    let (roster, _, _) = build_mixed_roster(0, &authority);
    let topo = build_topology(&roster, 3, &TopologyConfig::high_threat(), 1).unwrap();
    let config = GuardConfig {
        guard_count: GUARD_SET_SIZE,
        pin_mode: GuardPinMode::Rotate,
    };
    let guards = GuardSelector::new(&topo, &config, 42).unwrap();
    let set: HashSet<_> = guards.guard_set().iter().copied().collect();
    let mut seen = HashSet::new();
    for i in 0..GUARD_SET_SIZE as u64 * 3 {
        let entry = guards.entry_guard_for_packet(i);
        assert!(set.contains(&entry));
        seen.insert(entry);
    }
    assert_eq!(seen.len(), GUARD_SET_SIZE as usize, "rotate must visit all g guards");
}

#[test]
fn admission_rate_limit_caps_sybil_roster_growth_per_window() {
    let mut rng = OsRng;
    let authority = ConsortiumKey::generate(&mut rng);
    let pk = authority.verifying_key();

    // Seed honest pool under a permissive policy, then tighten rate limit so only
    // subsequent Sybil admits consume the 5/window quota.
    let mut roster =
        RelayRoster::with_admission_policy(RosterAdmissionPolicy::permissive_for_tests());
    let mut ledger = ReputationLedger::new(0.9).unwrap();
    for id in 1..=HONEST_COUNT {
        roster
            .admit_signed(authority.sign_record(&honest_record(id)), &pk, &mut ledger)
            .expect("honest admit");
        seed_vetted_reputation(&mut ledger, test_relay_id(id));
    }
    roster.set_admission_policy(RosterAdmissionPolicy {
        max_admissions_per_window: 5,
        window: Duration::from_secs(24 * 60 * 60),
        require_kem_derived_id: true,
    });
    roster.reset_admission_rate_limit();

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
        .map(|i| test_relay_id(20_000 + i))
        .collect();
    let m = measure_exposure(&roster, &sybil_ids, &ledger);
    eprintln!(
        "rate-limited flood: layer1_sybil={:.3} primary_g1={:.3} set_g3={:.3} \
         rep_path={:.3} rep_set={:.3} (pre-fix 50% rep_path ~{:.2})",
        m.layer1_sybil_fraction,
        m.primary_guard_sybil_rate,
        m.guard_set_any_sybil_rate,
        m.path_any_sybil_reputation_filtered,
        m.rep_guard_set_any_sybil_rate,
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
