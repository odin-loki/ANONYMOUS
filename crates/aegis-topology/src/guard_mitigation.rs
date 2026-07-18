//! Adaptive guard mitigation hooks (spec §13 — partial, v1–v4 presets).
//!
//! Ties Phase-7 anomaly / peer-health signals to guard rotation policy without
//! changing production defaults. Does **not** close §13 adaptive exposure.
//!
//! **Enforcement point:** clients select guards/paths; relay nodes load
//! `[guard_mitigation]` for operator symmetry only (see `docs/ops/adaptive_guard_mitigation.md`).

use serde::{Deserialize, Serialize};

use crate::guards::{GuardConfig, GuardPinMode};

/// When to force guard-set re-sample or pin-mode rotation after demotion / health spikes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardMitigationPolicy {
    /// Force guard re-sample after this many epochs on the same held set (hard sticky cap).
    pub max_sticky_epochs: u64,
    /// Soft sticky age: after this many epochs, apply deterministic decaying-stickiness
    /// re-sample pressure until [`Self::max_sticky_epochs`]. When `>= max_sticky_epochs`,
    /// soft band is disabled (v1/v2 behavior).
    pub soft_sticky_epochs: u64,
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
            soft_sticky_epochs: u64::MAX,
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
            soft_sticky_epochs: u64::MAX,
            rotate_on_anomaly: false,
            rotate_on_peer_health_spike: false,
            peer_health_spike_threshold: 3,
        }
    }

    /// First mitigation preset: cap sticky lifetime + rotate on anomaly / peer spike.
    pub const fn adaptive_first() -> Self {
        Self {
            max_sticky_epochs: 12,
            soft_sticky_epochs: 12,
            rotate_on_anomaly: true,
            rotate_on_peer_health_spike: true,
            peer_health_spike_threshold: 2,
        }
    }

    /// v2 preset — tighter sticky cap, lower peer spike threshold (sim-aligned v2).
    pub const fn adaptive_v2() -> Self {
        Self {
            max_sticky_epochs: 8,
            soft_sticky_epochs: 8,
            rotate_on_anomaly: true,
            rotate_on_peer_health_spike: true,
            peer_health_spike_threshold: 1,
        }
    }

    /// v3 preset — hard epoch-age cap 4, decaying stickiness from age 2, rotate on
    /// anomaly / single peer-health spike (sim `mode='mitigated_v3'`).
    ///
    /// Strong mid-horizon defense vs v2; long horizons still saturate — §13 [O].
    pub const fn adaptive_v3() -> Self {
        Self {
            max_sticky_epochs: 4,
            soft_sticky_epochs: 2,
            rotate_on_anomaly: true,
            rotate_on_peer_health_spike: true,
            peer_health_spike_threshold: 1,
        }
    }

    /// v4 preset — hard epoch-age cap 2, soft sticky from age 1 (sim `mode='mitigated_v4'`).
    ///
    /// Best in-tree sim long-horizon defense vs v3 at E=2000; still saturates — §13 [O].
    pub const fn adaptive_v4() -> Self {
        Self {
            max_sticky_epochs: 2,
            soft_sticky_epochs: 1,
            rotate_on_anomaly: true,
            rotate_on_peer_health_spike: true,
            peer_health_spike_threshold: 1,
        }
    }

    /// Deterministic decaying-stickiness soft re-sample in `[soft, hard)` ages.
    ///
    /// Probability of soft re-sample rises with age into the soft band (maps sim
    /// `stickiness_decay` pressure without requiring RNG at the policy layer).
    fn soft_sticky_resample(&self, epoch_age: u64) -> bool {
        if self.soft_sticky_epochs >= self.max_sticky_epochs {
            return false;
        }
        if epoch_age < self.soft_sticky_epochs {
            return false;
        }
        let into = epoch_age - self.soft_sticky_epochs + 1;
        let span = self
            .max_sticky_epochs
            .saturating_sub(self.soft_sticky_epochs)
            .max(1);
        // threshold grows toward ~100% as age approaches the hard cap
        let threshold = into.saturating_mul(100) / (span + 1);
        let roll = epoch_age.wrapping_mul(0x9E37_79B9_7F4A_7C15) % 100;
        roll < threshold
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
        if self.soft_sticky_resample(epoch_age) {
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

    /// Apply mitigation to `base` using [`GuardMitigationSignals`].
    pub fn apply_to_config_with_signals(
        &self,
        base: &GuardConfig,
        signals: &GuardMitigationSignals,
    ) -> GuardConfig {
        self.apply_to_config(
            base,
            signals.epoch_age,
            signals.anomaly_demotion_flag,
            signals.peer_anomaly_count,
        )
    }

    /// Client seed for guard re-sample when [`Self::should_resample_guards`] is true.
    pub fn client_seed_for_guards(
        &self,
        base_seed: u64,
        signals: &GuardMitigationSignals,
    ) -> u64 {
        if self.should_resample_guards(
            signals.epoch_age,
            signals.anomaly_demotion_flag,
            signals.peer_anomaly_count,
        ) {
            resample_guard_client_seed(base_seed, signals)
        } else {
            base_seed
        }
    }
}

/// Epoch-local signals fed into [`GuardMitigationPolicy`] at path/guard build time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuardMitigationSignals {
    /// Epochs since the held guard set was last re-sampled (0 at fresh sample).
    pub epoch_age: u64,
    /// True when pruning/anomaly demotion fired this epoch window.
    pub anomaly_demotion_flag: bool,
    /// Distinct peer-health anomaly flags this epoch (see `peer_health_spike_detected`).
    pub peer_anomaly_count: u32,
}

/// TOML `[guard_mitigation]` — opt-in sticky-cap + rotate-on-signal guard policy.
///
/// When omitted, or when neither `preset` nor legacy `adaptive_first = true` is set,
/// behavior matches production defaults ([`GuardMitigationPolicy::disabled()`]).
/// See `docs/ops/adaptive_guard_mitigation.md`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardMitigationFileConfig {
    /// Preset name: `"adaptive_first"` | `"adaptive_v2"` | `"adaptive_v3"` | `"adaptive_v4"`.
    /// Preferred over legacy bool.
    #[serde(default)]
    pub preset: Option<String>,
    /// Legacy enable for [`GuardMitigationPolicy::adaptive_first()`] when `preset` is absent.
    #[serde(default)]
    pub adaptive_first: bool,
}

impl GuardMitigationFileConfig {
    /// Resolve the effective mitigation policy for path/guard selection hooks.
    pub fn resolve_policy(&self) -> GuardMitigationPolicy {
        if let Some(ref name) = self.preset {
            return match name.as_str() {
                "adaptive_first" => GuardMitigationPolicy::adaptive_first(),
                "adaptive_v2" => GuardMitigationPolicy::adaptive_v2(),
                "adaptive_v3" => GuardMitigationPolicy::adaptive_v3(),
                "adaptive_v4" => GuardMitigationPolicy::adaptive_v4(),
                _ => GuardMitigationPolicy::disabled(),
            };
        }
        if self.adaptive_first {
            GuardMitigationPolicy::adaptive_first()
        } else {
            GuardMitigationPolicy::disabled()
        }
    }
}

/// Derive a fresh client seed when guard re-sample is required (deterministic for tests).
pub fn resample_guard_client_seed(base_seed: u64, signals: &GuardMitigationSignals) -> u64 {
    base_seed
        .wrapping_mul(0x5851_f42d_4c95_7f2d)
        .wrapping_add(signals.epoch_age.wrapping_mul(0x1405_7b7e_f767_814f))
        .wrapping_add(u64::from(signals.peer_anomaly_count))
        .wrapping_add(u64::from(signals.anomaly_demotion_flag))
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

    #[test]
    fn adaptive_v2_rotates_on_sticky_cap_and_single_peer_spike() {
        let p = GuardMitigationPolicy::adaptive_v2();
        assert!(p.should_resample_guards(8, false, 0));
        assert!(p.should_resample_guards(0, false, 1));
        assert!(!p.should_resample_guards(7, false, 0));
    }

    #[test]
    fn adaptive_v3_hard_cap_and_soft_sticky_band() {
        let p = GuardMitigationPolicy::adaptive_v3();
        assert_eq!(p.max_sticky_epochs, 4);
        assert_eq!(p.soft_sticky_epochs, 2);
        assert!(p.should_resample_guards(4, false, 0));
        assert!(p.should_resample_guards(0, false, 1));
        assert!(!p.should_resample_guards(0, false, 0));
        assert!(!p.should_resample_guards(1, false, 0));
        // Soft band: at least one age in [2, 4) must soft-resample (deterministic).
        let soft_hits = (2u64..4).filter(|&a| p.should_resample_guards(a, false, 0)).count();
        assert!(soft_hits >= 1, "v3 soft sticky band should fire for some ages");
    }

    #[test]
    fn file_config_preset_adaptive_v2() {
        let file = GuardMitigationFileConfig {
            preset: Some("adaptive_v2".into()),
            ..GuardMitigationFileConfig::default()
        };
        assert_eq!(file.resolve_policy(), GuardMitigationPolicy::adaptive_v2());
    }

    #[test]
    fn file_config_preset_adaptive_v3() {
        let file = GuardMitigationFileConfig {
            preset: Some("adaptive_v3".into()),
            ..GuardMitigationFileConfig::default()
        };
        assert_eq!(file.resolve_policy(), GuardMitigationPolicy::adaptive_v3());
    }

    #[test]
    fn adaptive_v4_hard_cap_and_soft_sticky_band() {
        let p = GuardMitigationPolicy::adaptive_v4();
        assert_eq!(p.max_sticky_epochs, 2);
        assert_eq!(p.soft_sticky_epochs, 1);
        assert!(p.should_resample_guards(2, false, 0));
        assert!(p.should_resample_guards(0, false, 1));
        assert!(!p.should_resample_guards(0, false, 0));
        // Soft band is active (soft < hard); age 0 never soft-resamples.
        assert!(p.soft_sticky_epochs < p.max_sticky_epochs);
        // Age 1 is in [soft, hard): deterministic soft roll may fire.
        let age1 = p.should_resample_guards(1, false, 0);
        let _ = age1;
    }

    #[test]
    fn file_config_preset_adaptive_v4() {
        let file = GuardMitigationFileConfig {
            preset: Some("adaptive_v4".into()),
            ..GuardMitigationFileConfig::default()
        };
        assert_eq!(file.resolve_policy(), GuardMitigationPolicy::adaptive_v4());
    }

    #[test]
    fn file_config_unknown_preset_is_disabled() {
        let file = GuardMitigationFileConfig {
            preset: Some("unknown".into()),
            ..GuardMitigationFileConfig::default()
        };
        assert_eq!(file.resolve_policy(), GuardMitigationPolicy::disabled());
    }

    #[test]
    fn file_config_preset_overrides_legacy_adaptive_first() {
        let file = GuardMitigationFileConfig {
            preset: Some("adaptive_v3".into()),
            adaptive_first: true,
            ..GuardMitigationFileConfig::default()
        };
        assert_eq!(file.resolve_policy(), GuardMitigationPolicy::adaptive_v3());
    }

    #[test]
    fn file_config_defaults_disabled() {
        let file = GuardMitigationFileConfig::default();
        assert!(file.preset.is_none());
        assert!(!file.adaptive_first);
        assert_eq!(file.resolve_policy(), GuardMitigationPolicy::disabled());
    }

    #[test]
    fn client_seed_unchanged_when_not_resampling() {
        let p = GuardMitigationPolicy::adaptive_first();
        let signals = GuardMitigationSignals::default();
        assert_eq!(p.client_seed_for_guards(42, &signals), 42);
    }

    #[test]
    fn client_seed_resamples_on_sticky_cap() {
        let p = GuardMitigationPolicy::adaptive_first();
        let signals = GuardMitigationSignals {
            epoch_age: 12,
            ..GuardMitigationSignals::default()
        };
        assert_ne!(p.client_seed_for_guards(42, &signals), 42);
    }

    #[test]
    fn client_seed_resamples_on_v3_hard_cap() {
        let p = GuardMitigationPolicy::adaptive_v3();
        let signals = GuardMitigationSignals {
            epoch_age: 4,
            ..GuardMitigationSignals::default()
        };
        assert_ne!(p.client_seed_for_guards(42, &signals), 42);
    }

    #[test]
    fn client_seed_resamples_on_v4_hard_cap() {
        let p = GuardMitigationPolicy::adaptive_v4();
        let signals = GuardMitigationSignals {
            epoch_age: 2,
            ..GuardMitigationSignals::default()
        };
        assert_ne!(p.client_seed_for_guards(42, &signals), 42);
    }
}
