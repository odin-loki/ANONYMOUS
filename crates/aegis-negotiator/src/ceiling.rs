//! F_max file-size ceiling and fragmentation (spec §5.3, §6).
//!
//! ## F_max formula reconciliation
//!
//! Spec §5.3 prose states `F_max = cover_budget × round_period` with worked examples:
//!
//! | cover budget | round period | stated F_max |
//! |--------------|--------------|--------------|
//! | 10 MB/s      | 60 s         | 120 MB       |
//! | 50 MB/s      | 5 min        | 3 GB         |
//! | 200 MB/s     | 15 min       | 36 GB        |
//!
//! The naive product `cover × period` gives 600 MB, 15 GB, and 180 GB respectively —
//! none match the spec's headline numbers.
//!
//! The Python reference [`bulk_size_ceiling`](../../sim/aegis_sim/metrics.py) implements:
//!
//! ```text
//! F_max = cover_budget × round_period / max(c_flows − avg_real, 1)
//! ```
//!
//! with defaults `c_flows = 8`, `avg_real = 3` (slack divisor 5). That reproduces all
//! three worked examples exactly:
//!
//! - 10×10⁶ × 60 / 5 = 120×10⁶ bytes (120 MB)
//! - 50×10⁶ × 300 / 5 = 3×10⁹ bytes (3 GB)
//! - 200×10⁶ × 900 / 5 = 36×10⁹ bytes (36 GB)
//!
//! **Conclusion:** treat `metrics.py::bulk_size_ceiling` as ground truth; §5.3 prose is
//! an abbreviated gloss that omits the slack divisor accounting for cover-flow budget
//! (`c_flows − avg_real`). [`f_max`] implements the slack-adjusted formula; [`f_max_prose`]
//! exposes the simplified product for documentation comparisons.

use thiserror::Error;

/// Default total cover-flow slots per round (Python `c_flows`).
pub const DEFAULT_C_FLOWS: u32 = 8;
/// Default average real participant flows consuming cover budget (Python `avg_real`).
pub const DEFAULT_AVG_REAL: u32 = 3;

/// Policy when `file_size > F_max` (spec §5.3: fragment or accept exposure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Split into chunks each ≤ F_max (pays mixnet-class cost per fragment).
    Fragment,
    /// Transfer whole file above ceiling; caller accepts relationship exposure.
    AcceptExposure,
}

/// Planned bulk transfer respecting (or explicitly overriding) the size ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BulkPlan {
    /// Single transfer within F_max.
    Single { size_bytes: u64 },
    /// File fragmented into F_max-sized pieces.
    Fragment {
        chunks: Vec<u64>,
        f_max_bytes: u64,
    },
    /// Whole file above F_max; caller opted into exposure.
    AcceptExposure {
        size_bytes: u64,
        f_max_bytes: u64,
    },
}

#[derive(Debug, Error, PartialEq)]
pub enum NegotiatorError {
    #[error("invalid F_max: must be positive, got {0}")]
    InvalidCeiling(f64),
    #[error("file size {file_size_bytes} exceeds F_max {f_max_bytes}; fragmentation required (use OverflowPolicy::Fragment)")]
    ExceedsCeilingRequiresFragment {
        file_size_bytes: u64,
        f_max_bytes: u64,
    },
}

/// Slack-adjusted confirmation-resistant file-size ceiling (matches `metrics.py`).
///
/// `F_max = cover_budget × round_period / max(c_flows − avg_real, 1)`
#[must_use]
pub fn f_max(
    cover_budget_bytes_per_s: f64,
    round_period_s: f64,
    c_flows: u32,
    avg_real: u32,
) -> f64 {
    let slack = c_flows.saturating_sub(avg_real).max(1) as f64;
    cover_budget_bytes_per_s * round_period_s / slack
}

/// Convenience wrapper with Python default slack parameters.
#[must_use]
pub fn f_max_default(cover_budget_bytes_per_s: f64, round_period_s: f64) -> f64 {
    f_max(
        cover_budget_bytes_per_s,
        round_period_s,
        DEFAULT_C_FLOWS,
        DEFAULT_AVG_REAL,
    )
}

/// Simplified spec-prose formula without slack divisor: `cover × period`.
#[must_use]
pub fn f_max_prose(cover_budget_bytes_per_s: f64, round_period_s: f64) -> f64 {
    cover_budget_bytes_per_s * round_period_s
}

/// Enforce the F_max ceiling on a planned bulk transfer.
pub fn enforce_ceiling(
    file_size_bytes: u64,
    f_max_bytes: f64,
    policy: OverflowPolicy,
) -> Result<BulkPlan, NegotiatorError> {
    if f_max_bytes <= 0.0 || !f_max_bytes.is_finite() {
        return Err(NegotiatorError::InvalidCeiling(f_max_bytes));
    }

    let ceiling = f_max_bytes.floor() as u64;
    if ceiling == 0 {
        return Err(NegotiatorError::InvalidCeiling(f_max_bytes));
    }

    if file_size_bytes <= ceiling {
        return Ok(BulkPlan::Single {
            size_bytes: file_size_bytes,
        });
    }

    match policy {
        OverflowPolicy::Fragment => {
            let chunks = fragment_sizes(file_size_bytes, ceiling);
            Ok(BulkPlan::Fragment {
                chunks,
                f_max_bytes: ceiling,
            })
        }
        OverflowPolicy::AcceptExposure => Ok(BulkPlan::AcceptExposure {
            size_bytes: file_size_bytes,
            f_max_bytes: ceiling,
        }),
    }
}

/// Compute chunk sizes for fragmentation (all full chunks except possibly the last).
#[must_use]
pub fn fragment_sizes(file_size_bytes: u64, chunk_max_bytes: u64) -> Vec<u64> {
    assert!(chunk_max_bytes > 0, "chunk_max_bytes must be positive");
    if file_size_bytes == 0 {
        return vec![0];
    }
    let full = file_size_bytes / chunk_max_bytes;
    let rem = file_size_bytes % chunk_max_bytes;
    let mut chunks = Vec::with_capacity(full as usize + if rem > 0 { 1 } else { 0 });
    chunks.extend((0..full).map(|_| chunk_max_bytes));
    if rem > 0 {
        chunks.push(rem);
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1.0;

    #[test]
    fn f_max_matches_spec_worked_examples_via_slack() {
        assert!((f_max_default(10e6, 60.0) - 120e6).abs() < EPS);
        assert!((f_max_default(50e6, 300.0) - 3e9).abs() < EPS);
        assert!((f_max_default(200e6, 900.0) - 36e9).abs() < EPS);
    }

    #[test]
    fn f_max_prose_is_five_times_slack_adjusted_with_defaults() {
        let cover = 10e6;
        let period = 60.0;
        assert!((f_max_prose(cover, period) - 5.0 * f_max_default(cover, period)).abs() < EPS);
    }

    #[test]
    fn f_max_slack_divisor_minimum_one() {
        let raw = f_max(1e6, 10.0, 2, 5);
        assert!((raw - 10e6).abs() < EPS);
    }

    #[test]
    fn enforce_within_ceiling_single() {
        let plan = enforce_ceiling(100, 120e6, OverflowPolicy::Fragment).unwrap();
        assert_eq!(plan, BulkPlan::Single { size_bytes: 100 });
    }

    #[test]
    fn enforce_fragment_splits_correctly() {
        let f_max_bytes = 120e6;
        let file = 250_000_000u64;
        let plan = enforce_ceiling(file, f_max_bytes, OverflowPolicy::Fragment).unwrap();
        match plan {
            BulkPlan::Fragment { chunks, f_max_bytes: cap } => {
                assert_eq!(cap, f_max_bytes as u64);
                assert_eq!(chunks, vec![120_000_000, 120_000_000, 10_000_000]);
                assert_eq!(chunks.iter().sum::<u64>(), file);
                assert!(chunks.iter().all(|&c| c <= cap));
            }
            _ => panic!("expected Fragment"),
        }
    }

    #[test]
    fn enforce_accept_exposure() {
        let plan = enforce_ceiling(500e6 as u64, 120e6, OverflowPolicy::AcceptExposure).unwrap();
        assert_eq!(
            plan,
            BulkPlan::AcceptExposure {
                size_bytes: 500_000_000,
                f_max_bytes: 120_000_000,
            }
        );
    }

    #[test]
    fn enforce_invalid_ceiling() {
        assert_eq!(
            enforce_ceiling(100, 0.0, OverflowPolicy::Fragment),
            Err(NegotiatorError::InvalidCeiling(0.0))
        );
    }

    #[test]
    fn fragment_sizes_exact_multiple() {
        assert_eq!(fragment_sizes(300, 100), vec![100, 100, 100]);
    }

    #[test]
    fn fragment_sizes_with_remainder() {
        assert_eq!(fragment_sizes(250, 100), vec![100, 100, 50]);
    }
}
