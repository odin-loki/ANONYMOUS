//! GPA-safer external export of coarse relay / ingress counters.
//!
//! Raw [`crate::node::RelayHandle::coarse_stats`] and
//! [`crate::net::IngressRateLimitStats::dropped_frames`] remain available for
//! in-process tests. External scrapers (ops dashboards, Prometheus) should use
//! [`MetricsExportGate`] so production defaults enforce:
//!
//! - **min scrape cadence** (default 30s) — deny too-frequent exports
//! - **quantize** — coarser counter buckets (blur high-res deltas)
//! - **suppress ingress drop detail** — hide `dropped_frames` unless high-res
//!
//! Opt-in [`MetricsExportConfig::lab_high_resolution`] disables all three for
//! lab captures. Privileged observers with raw handle / debug access remain a
//! residual (honest: not closed).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::node::RelayCoarseStats;

/// Production default: poll external coarse metrics at most once per 30s.
pub const DEFAULT_MIN_SCRAPE_INTERVAL_SECS: u64 = 30;

/// Production default quantization bucket for exported counters.
pub const DEFAULT_QUANTIZE_BUCKET: u64 = 16;

/// Export policy for external-facing coarse metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct MetricsExportConfig {
    /// Minimum wall time between successful external exports.
    ///
    /// Ignored when [`Self::allow_high_resolution`] is true. Set to
    /// [`Duration::ZERO`] to disable cadence (not recommended for production).
    pub min_scrape_interval: Duration,
    /// Floor counters to multiples of this bucket (`0` = no quantization).
    pub quantize_bucket: u64,
    /// When true, skip cadence / quantize / drop-suppression (lab / privileged).
    pub allow_high_resolution: bool,
    /// When true (and not high-res), omit ingress `dropped_frames` from export.
    pub suppress_ingress_drop_detail: bool,
}

impl Default for MetricsExportConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl MetricsExportConfig {
    /// Safer production defaults (cadence + quantize + suppress drops detail).
    pub fn production() -> Self {
        Self {
            min_scrape_interval: Duration::from_secs(DEFAULT_MIN_SCRAPE_INTERVAL_SECS),
            quantize_bucket: DEFAULT_QUANTIZE_BUCKET,
            allow_high_resolution: false,
            suppress_ingress_drop_detail: true,
        }
    }

    /// Lab / privileged high-resolution export (opt-in; GPA residual under flood).
    pub fn lab_high_resolution() -> Self {
        Self {
            min_scrape_interval: Duration::ZERO,
            quantize_bucket: 0,
            allow_high_resolution: true,
            suppress_ingress_drop_detail: false,
        }
    }

    pub fn is_hardened(&self) -> bool {
        !self.allow_high_resolution
            && (self.min_scrape_interval > Duration::ZERO
                || self.quantize_bucket > 1
                || self.suppress_ingress_drop_detail)
    }
}

/// Snapshot safe for external scrapers after policy application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportedRelayStats {
    pub coarse: RelayCoarseStats,
    /// `None` when ingress drop detail is suppressed by policy.
    pub ingress_dropped_frames: Option<u64>,
}

/// Why an external export was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsExportError {
    /// Caller scraped faster than [`MetricsExportConfig::min_scrape_interval`].
    TooSoon { retry_after: Duration },
}

impl std::fmt::Display for MetricsExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooSoon { retry_after } => {
                write!(
                    f,
                    "metrics export denied: min scrape cadence not elapsed (retry after {retry_after:?})"
                )
            }
        }
    }
}

impl std::error::Error for MetricsExportError {}

/// Stateful gate: enforces cadence across scrapes; applies quantize / suppress.
#[derive(Debug)]
pub struct MetricsExportGate {
    config: MetricsExportConfig,
    last_ok: Mutex<Option<Instant>>,
}

impl MetricsExportGate {
    pub fn new(config: MetricsExportConfig) -> Self {
        Self {
            config,
            last_ok: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &MetricsExportConfig {
        &self.config
    }

    /// Export using wall-clock [`Instant::now`].
    pub fn export(
        &self,
        coarse: RelayCoarseStats,
        ingress_dropped_frames: u64,
    ) -> Result<ExportedRelayStats, MetricsExportError> {
        self.export_at(coarse, ingress_dropped_frames, Instant::now())
    }

    /// Deterministic export for tests (inject `now`).
    pub fn export_at(
        &self,
        coarse: RelayCoarseStats,
        ingress_dropped_frames: u64,
        now: Instant,
    ) -> Result<ExportedRelayStats, MetricsExportError> {
        let cfg = &self.config;
        if !cfg.allow_high_resolution && cfg.min_scrape_interval > Duration::ZERO {
            let mut guard = self.last_ok.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(prev) = *guard {
                let elapsed = now.saturating_duration_since(prev);
                if elapsed < cfg.min_scrape_interval {
                    return Err(MetricsExportError::TooSoon {
                        retry_after: cfg.min_scrape_interval - elapsed,
                    });
                }
            }
            *guard = Some(now);
        }

        let coarse = if cfg.allow_high_resolution {
            coarse
        } else {
            quantize_coarse(coarse, cfg.quantize_bucket)
        };

        let ingress_dropped_frames = if cfg.allow_high_resolution {
            Some(ingress_dropped_frames)
        } else if cfg.suppress_ingress_drop_detail {
            None
        } else {
            Some(quantize_u64(ingress_dropped_frames, cfg.quantize_bucket))
        };

        Ok(ExportedRelayStats {
            coarse,
            ingress_dropped_frames,
        })
    }
}

/// Floor `v` to a multiple of `bucket` (`0`/`1` → identity).
pub fn quantize_u64(v: u64, bucket: u64) -> u64 {
    if bucket <= 1 {
        v
    } else {
        v / bucket * bucket
    }
}

pub fn quantize_coarse(stats: RelayCoarseStats, bucket: u64) -> RelayCoarseStats {
    RelayCoarseStats {
        processed_ok: quantize_u64(stats.processed_ok, bucket),
        processed_fail: quantize_u64(stats.processed_fail, bucket),
        cover_emitted: quantize_u64(stats.cover_emitted, bucket),
        queue_dropped: quantize_u64(stats.queue_dropped, bucket),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_coarse() -> RelayCoarseStats {
        RelayCoarseStats {
            processed_ok: 37,
            processed_fail: 9,
            cover_emitted: 21,
            queue_dropped: 5,
        }
    }

    #[test]
    fn production_defaults_are_hardened() {
        let cfg = MetricsExportConfig::production();
        assert_eq!(
            cfg.min_scrape_interval,
            Duration::from_secs(DEFAULT_MIN_SCRAPE_INTERVAL_SECS)
        );
        assert_eq!(cfg.quantize_bucket, DEFAULT_QUANTIZE_BUCKET);
        assert!(!cfg.allow_high_resolution);
        assert!(cfg.suppress_ingress_drop_detail);
        assert!(cfg.is_hardened());
    }

    #[test]
    fn lab_high_res_passes_raw_and_drops() {
        let gate = MetricsExportGate::new(MetricsExportConfig::lab_high_resolution());
        let t0 = Instant::now();
        let a = gate.export_at(sample_coarse(), 123, t0).unwrap();
        assert_eq!(a.coarse, sample_coarse());
        assert_eq!(a.ingress_dropped_frames, Some(123));
        // No cadence: immediate re-export ok.
        let b = gate
            .export_at(sample_coarse(), 124, t0 + Duration::from_millis(1))
            .unwrap();
        assert_eq!(b.ingress_dropped_frames, Some(124));
    }

    #[test]
    fn production_enforces_min_cadence() {
        let gate = MetricsExportGate::new(MetricsExportConfig::production());
        let t0 = Instant::now();
        assert!(gate.export_at(sample_coarse(), 50, t0).is_ok());
        let err = gate
            .export_at(sample_coarse(), 50, t0 + Duration::from_secs(5))
            .unwrap_err();
        match err {
            MetricsExportError::TooSoon { retry_after } => {
                assert!(retry_after > Duration::from_secs(20));
                assert!(retry_after <= Duration::from_secs(DEFAULT_MIN_SCRAPE_INTERVAL_SECS));
            }
        }
        assert!(gate
            .export_at(
                sample_coarse(),
                50,
                t0 + Duration::from_secs(DEFAULT_MIN_SCRAPE_INTERVAL_SECS)
            )
            .is_ok());
    }

    #[test]
    fn production_quantizes_and_suppresses_drops() {
        let gate = MetricsExportGate::new(MetricsExportConfig::production());
        let out = gate
            .export_at(sample_coarse(), 99, Instant::now())
            .unwrap();
        assert_eq!(out.coarse.processed_ok, 32); // 37 → 32
        assert_eq!(out.coarse.processed_fail, 0); // 9 → 0
        assert_eq!(out.coarse.cover_emitted, 16);
        assert_eq!(out.coarse.queue_dropped, 0);
        assert_eq!(out.ingress_dropped_frames, None);
    }

    #[test]
    fn quantize_without_suppress_keeps_bucketed_drops() {
        let cfg = MetricsExportConfig {
            min_scrape_interval: Duration::ZERO,
            quantize_bucket: 10,
            allow_high_resolution: false,
            suppress_ingress_drop_detail: false,
        };
        let gate = MetricsExportGate::new(cfg);
        let out = gate
            .export_at(sample_coarse(), 99, Instant::now())
            .unwrap();
        assert_eq!(out.coarse.processed_ok, 30);
        assert_eq!(out.ingress_dropped_frames, Some(90));
    }

    #[test]
    fn quantize_u64_identity_for_bucket_0_or_1() {
        assert_eq!(quantize_u64(42, 0), 42);
        assert_eq!(quantize_u64(42, 1), 42);
        assert_eq!(quantize_u64(42, 16), 32);
    }
}
