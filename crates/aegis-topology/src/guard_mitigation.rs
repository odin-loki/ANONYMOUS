//! Adaptive guard mitigation hooks (spec §13 first mitigation — partial).
//!
//! Ties Phase-7 anomaly / peer-health signals to guard rotation policy without
//! changing production defaults. Does **not** close §13 adaptive exposure.

use crate::guards::{GuardConfig, GuardPinMode};

/// When to force guard-set re-sample or pin-mode rotation after demotion / health spikes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardMitigationPolicy {
    /// Force guard re-sample after this many epochs on the same held set (sticky cap).
    pub max_sticky_epochs: u64,
    /// Re-sample + rotate pin when an anomaly demotion flag is observed this epoch.
    pub rotate_on_anomaly: bool,
    /// Re-sample + rotate when peer-health anomaly count crosses [`Self::peer_health_spike_threshold`].
    pub rotate_on_peer_health_spike: bool,
    /// Count of distinct peer anomaly flags in the epoch window that triggers rotation.
    pub peer_health_spike_threshold: u32,
}

impl Default for GuardMitigationPolicy {
    /// Production-safe: no forced rotation (sticky primary unchanged).
    fn default() -> Self {
        Self {
            max_sticky_epochs: u64::MAX,
            rotate_on_anomaly: false,
            rotate_on_peer_health_spike: false,
            peer_health_spike_threshold: 3,
        }
    }
}

impl GuardMitigationPolicy {
    /// Disabled mitigation — identical to pre-mitigation production behavior.
    pub const fn disabled() -> Self {
        Self {
            max_sticky_epochs: u64::MAX,
            rotate_on_anomaly: false,
            rotate_on_peer_health_spike: false,
            peer_health_spike_threshold: 3,
        }
    }

    /// First mitigation preset: cap sticky lifetime + rotate on anomaly / peer spike.
    pub const fn adaptive_first() -> Self {
        Self {
            max_sticky_epochs: 12,
            rotate_on_anomaly: true,
            rotate_on_peer_health_spike: true,
            peer_health_spike_threshold: 2,
        }
    }

    /// Whether the held guard set should be re-sampled for the next epoch.
    pub fn should_resample_guards(
        &self,
        epoch_age: u64,
        anomaly_demotion_flag: bool,
        peer_anomaly_count: u32,
    ) -> bool {
        if epoch_age >= self.max_sticky_epochs {
            return true;
        }
        if self.rotate_on_anomaly && anomaly_demotion_flag {
            return true;
        }
        if self.rotate_on_peer_health_spike
            && peer_anomaly_count >= self.peer_health_spike_threshold
        {
            return true;
        }
        false
    }

    /// Pin mode for path builders after applying mitigation (rotate under signal).
    pub fn pin_mode_for_epoch(
        &self,
        base: GuardPinMode,
        epoch_age: u64,
        anomaly_demotion_flag: bool,
        peer_anomaly_count: u32,
    ) -> GuardPinMode {
        if self.should_resample_guards(epoch_age, anomaly_demotion_flag, peer_anomaly_count) {
            GuardPinMode::Rotate
        } else {
            base
        }
    }

    /// Apply mitigation to a [`GuardConfig`] when signals fire (defaults preserved otherwise).
    pub fn apply_to_config(
        &self,
        base: &GuardConfig,
        epoch_age: u64,
        anomaly_demotion_flag: bool,
        peer_anomaly_count: u32,
    ) -> GuardConfig {
        let mut cfg = *base;
        cfg.pin_mode = self.pin_mode_for_epoch(
            base.pin_mode,
            epoch_age,
            anomaly_demotion_flag,
            peer_anomaly_count,
        );
        cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_never_resamples_or_rotates() {
        let p = GuardMitigationPolicy::disabled();
        assert!(!p.should_resample_guards(1000, true, 99));
        assert_eq!(
            p.pin_mode_for_epoch(GuardPinMode::StickyPrimary, 1000, true, 99),
            GuardPinMode::StickyPrimary
        );
    }

    #[test]
    fn adaptive_first_rotates_on_anomaly_and_sticky_cap() {
        let p = GuardMitigationPolicy::adaptive_first();
        assert!(p.should_resample_guards(12, false, 0));
        assert!(p.should_resample_guards(1, true, 0));
        assert!(p.should_resample_guards(0, false, 2));
        assert_eq!(
            p.pin_mode_for_epoch(GuardPinMode::StickyPrimary, 1, true, 0),
            GuardPinMode::Rotate
        );
    }

    #[test]
    fn apply_to_config_preserves_guard_count() {
        let base = GuardConfig::default();
        let p = GuardMitigationPolicy::adaptive_first();
        let out = p.apply_to_config(&base, 0, false, 0);
        assert_eq!(out.guard_count, base.guard_count);
        assert_eq!(out.pin_mode, GuardPinMode::StickyPrimary);
        let out2 = p.apply_to_config(&base, 0, true, 0);
        assert_eq!(out2.pin_mode, GuardPinMode::Rotate);
    }
}
