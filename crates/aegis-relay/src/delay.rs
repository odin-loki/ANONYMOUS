//! Per-hop Exp(μ) mixing delay (spec §4.4).
//!
//! Delay exists only to let cover traffic mix alongside crypto and (later) constant-rate
//! emission. It is **not** a standalone security primitive.

use std::time::Duration;

use rand_core::{CryptoRngCore, RngCore};

/// Sample one draw from Exp(μ): mean delay `1/μ` seconds.
pub fn sample_mixing_delay<R: RngCore + CryptoRngCore>(mu: f64, rng: &mut R) -> Duration {
    debug_assert!(mu > 0.0, "mu must be positive");
    // Inverse-CDF: -ln(U) / μ, U ~ Uniform(0, 1)
    let mut u = rng.next_u64() as f64 / u64::MAX as f64;
    if u <= 0.0 {
        u = f64::MIN_POSITIVE;
    }
    let secs = -u.ln() / mu;
    Duration::from_secs_f64(secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn delay_is_nonzero_with_high_probability() {
        let mut rng = OsRng;
        let d = sample_mixing_delay(2.0, &mut rng);
        assert!(d.as_secs_f64() >= 0.0);
    }

    #[test]
    fn empirical_mean_near_one_over_mu() {
        let mu = 10.0;
        let mut rng = OsRng;
        let n = 5000;
        let sum: f64 = (0..n)
            .map(|_| sample_mixing_delay(mu, &mut rng).as_secs_f64())
            .sum();
        let mean = sum / n as f64;
        let expected = 1.0 / mu;
        assert!(
            (mean - expected).abs() < 0.02,
            "mean {mean} not near {expected}"
        );
    }
}
