//! Relay configuration — mixing delay parameter `mu` (spec §4.4, §7).

/// Default rate parameter for per-hop Exp(μ) mixing delay.
///
/// # Parameter budget (spec §7, L = 4)
///
/// End-to-end mixing latency target: **~2 s mean / ~5 s p99** across the path.
/// Each hop draws an independent delay `D ~ Exp(μ)` with **E[D] = 1/μ**.
/// For `L = 4` hops, **E[total] = L/μ**.
///
/// Choosing **μ = 2.0** (per second):
/// - mean per-hop delay = 1/μ = **0.5 s**
/// - mean path mixing delay = 4 × 0.5 s = **2.0 s** (matches §7 mixing mean)
///
/// The p99 path tail is looser than the mean (sum of four Exp draws); this is a
/// soft tuning target, not a hard gate.
pub const DEFAULT_MU: f64 = 2.0;

/// Per-relay configuration.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Rate parameter μ for Exp(μ) per-hop mixing delay (mean delay = 1/μ).
    pub mu: f64,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self { mu: DEFAULT_MU }
    }
}

impl RelayConfig {
    pub fn new(mu: f64) -> Self {
        Self { mu }
    }
}
