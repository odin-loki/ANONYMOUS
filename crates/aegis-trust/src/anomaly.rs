//! Generic statistical anomaly detector (spec §4.8, §7 references
//! "Izaac/GRIA anomaly detection").
//!
//! This is NOT a reproduction of the specific published Izaac/GRIA method named
//! in the spec — this codebase does not have verified access to that method's
//! exact algorithm, and inventing a same-named-but-different implementation
//! would be misleading. Instead, this module provides a generic, real,
//! well-tested EWMA mean/variance z-score detector that plays the same
//! structural role (flag a relay whose observed behavior — e.g. loop-cover
//! return rate, drop rate, latency — deviates significantly from its own recent
//! history) so the rest of the trust pipeline (feeding [`crate::reputation`])
//! has something concrete to consume. Swap in the actual named method later if/
//! when its specification is available to implement faithfully.

/// Online EWMA mean/variance tracker + z-score anomaly flagging for a single
/// scalar metric stream (e.g. one relay's per-epoch drop rate).
pub struct AnomalyDetector {
    alpha: f64,
    mean: f64,
    var: f64,
    n: u64,
    z_threshold: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnomalyVerdict {
    pub z_score: f64,
    pub is_anomalous: bool,
}

impl AnomalyDetector {
    /// `alpha` in `(0,1]` controls EWMA responsiveness (smaller = longer memory).
    /// `z_threshold` (e.g. 3.0) is how many standard deviations away from the
    /// running mean counts as anomalous.
    pub fn new(alpha: f64, z_threshold: f64) -> Self {
        Self {
            alpha: alpha.clamp(1e-6, 1.0),
            mean: 0.0,
            var: 0.0,
            n: 0,
            z_threshold,
        }
    }

    /// Feed one new observation; returns the verdict for THIS observation
    /// (evaluated against the mean/variance BEFORE this observation updates
    /// them, so a single huge spike is judged against prior history, not itself).
    pub fn observe(&mut self, x: f64) -> AnomalyVerdict {
        let verdict = if self.n < 2 {
            // Not enough history to judge; never flag the first couple of points.
            AnomalyVerdict {
                z_score: 0.0,
                is_anomalous: false,
            }
        } else {
            let std = self.var.sqrt().max(1e-9);
            let z = (x - self.mean) / std;
            AnomalyVerdict {
                z_score: z,
                is_anomalous: z.abs() > self.z_threshold,
            }
        };

        let delta = x - self.mean;
        self.mean += self.alpha * delta;
        self.var = (1.0 - self.alpha) * (self.var + self.alpha * delta * delta);
        self.n += 1;

        verdict
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn observations(&self) -> u64 {
        self.n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_stream_is_not_flagged() {
        let mut det = AnomalyDetector::new(0.2, 3.0);
        let mut flagged = 0;
        for i in 0..200 {
            // small deterministic wobble around 10.0, no real anomalies
            let x = 10.0 + ((i % 5) as f64 - 2.0) * 0.1;
            if det.observe(x).is_anomalous {
                flagged += 1;
            }
        }
        assert_eq!(flagged, 0, "stable low-variance stream should not be flagged");
    }

    #[test]
    fn sudden_spike_is_flagged() {
        let mut det = AnomalyDetector::new(0.2, 3.0);
        for _ in 0..100 {
            det.observe(10.0);
        }
        let verdict = det.observe(1000.0);
        assert!(verdict.is_anomalous, "huge spike vs. stable history should be flagged");
        assert!(verdict.z_score > 3.0);
    }

    #[test]
    fn detector_adapts_after_sustained_shift() {
        let mut det = AnomalyDetector::new(0.3, 3.0);
        for _ in 0..50 {
            det.observe(10.0);
        }
        // sustained shift to a new level -- detector should adapt and eventually
        // stop flagging the new level as anomalous
        let mut later_flags = 0;
        for i in 0..50 {
            let v = det.observe(50.0);
            if i > 30 && v.is_anomalous {
                later_flags += 1;
            }
        }
        assert_eq!(later_flags, 0, "detector should adapt to a sustained level shift");
    }

    #[test]
    fn first_two_observations_never_flagged() {
        let mut det = AnomalyDetector::new(0.5, 1.0);
        assert!(!det.observe(0.0).is_anomalous);
        assert!(!det.observe(1_000_000.0).is_anomalous);
    }
}
