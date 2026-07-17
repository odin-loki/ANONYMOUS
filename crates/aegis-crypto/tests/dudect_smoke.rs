//! Stronger timing smoke for `ReplayCache::contains_ct` hit vs miss paths.
//!
//! This is **not** a `dudect` proof. It compares median latencies and a coarse
//! Mann–Whitney-style rank check so gross data-dependent skew fails CI.
//! For rigorous evidence, run `dudect` under WSL — see
//! `docs/ops/constant_time_ci.md`.

use aegis_crypto::replay::{ReplayCache, ReplayTag};
use std::time::Instant;

fn tag(n: u64) -> ReplayTag {
    let mut t = [0u8; 32];
    t[..8].copy_from_slice(&n.to_le_bytes());
    t
}

fn median_ns(samples: &mut [u64]) -> u64 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Two-sample rank statistic: fraction of (hit, miss) pairs with hit > miss.
/// Under identical distributions this concentrates near 0.5.
fn rank_hit_gt_miss(hit: &[u64], miss: &[u64]) -> f64 {
    let mut gt = 0u64;
    let mut total = 0u64;
    for &h in hit {
        for &m in miss {
            total += 1;
            if h > m {
                gt += 1;
            }
        }
    }
    gt as f64 / total.max(1) as f64
}

#[test]
fn ct_contains_hit_miss_timing_smoke() {
    const CAP: usize = 64;
    const TRIALS: usize = 3_000;
    const WARMUP: usize = 200;

    let mut cache = ReplayCache::with_capacity(CAP);
    for i in 0..CAP {
        assert!(cache.check_and_insert(tag(i as u64)));
    }
    let hit_tag = tag(0);
    let miss_tag = tag(9_000);

    assert!(cache.contains_ct(&hit_tag));
    assert!(!cache.contains_ct(&miss_tag));

    let mut hit_times = Vec::with_capacity(TRIALS);
    let mut miss_times = Vec::with_capacity(TRIALS);

    for i in 0..(WARMUP + TRIALS) {
        // Alternate order each trial to reduce systematic bias.
        if i % 2 == 0 {
            let t0 = Instant::now();
            let _ = std::hint::black_box(cache.contains_ct(&hit_tag));
            let ht = t0.elapsed().as_nanos() as u64;
            let t1 = Instant::now();
            let _ = std::hint::black_box(cache.contains_ct(&miss_tag));
            let mt = t1.elapsed().as_nanos() as u64;
            if i >= WARMUP {
                hit_times.push(ht);
                miss_times.push(mt);
            }
        } else {
            let t0 = Instant::now();
            let _ = std::hint::black_box(cache.contains_ct(&miss_tag));
            let mt = t0.elapsed().as_nanos() as u64;
            let t1 = Instant::now();
            let _ = std::hint::black_box(cache.contains_ct(&hit_tag));
            let ht = t1.elapsed().as_nanos() as u64;
            if i >= WARMUP {
                hit_times.push(ht);
                miss_times.push(mt);
            }
        }
    }

    let hit_med = median_ns(&mut hit_times.clone());
    let miss_med = median_ns(&mut miss_times.clone());
    let ratio = if hit_med > miss_med {
        hit_med as f64 / miss_med.max(1) as f64
    } else {
        miss_med as f64 / hit_med.max(1) as f64
    };

    // Coarse guard: medians should not diverge by more than 2.5× on a noisy host.
    assert!(
        ratio < 2.5,
        "ct_contains hit/miss median ratio too large: hit={hit_med}ns miss={miss_med}ns ratio={ratio:.2}"
    );

    // Rank check: P(hit > miss) should stay near 0.5 (allow noisy Windows timers).
    let p = rank_hit_gt_miss(&hit_times, &miss_times);
    assert!(
        (0.20..=0.80).contains(&p),
        "ct_contains rank P(hit>miss)={p:.3} outside [0.20, 0.80] (hit_med={hit_med} miss_med={miss_med})"
    );
}
