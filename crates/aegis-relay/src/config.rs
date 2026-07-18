//! Relay configuration — mixing delay parameter `mu` (spec §4.4, §7)
//! and optional bulk cover-flow policy (spec §5.2 L2).

use aegis_negotiator::cover::{l2_cover_requirement, CoverRequirement};
use aegis_negotiator::dial::{dial_requires_relay_cover, SecurityDial, L2_BASELINE_CONCURRENCY};

use crate::cover_flow::{
    CoverFlowConfig, CoverMultihopDefense, CoverOnionTerminal, DEFAULT_COVER_ONION_FLOWS,
    DEFAULT_MATCHED_COVER_FLOWS,
};

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

/// Default observed-flow target for L2 bulk cover rounds ([`L2_BASELINE_CONCURRENCY`]).
pub const DEFAULT_COVER_TARGET_FLOW_COUNT: u32 = L2_BASELINE_CONCURRENCY as u32;

/// Default bulk-round rotation interval when cover is enabled (seconds).
pub const DEFAULT_COVER_ROUND_SECS: u64 = 30;

/// Error when bulk cover policy is required but cannot be satisfied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoverPolicyError {
    #[error("bulk cover is required by config but the cover outbound channel is absent")]
    CoverChannelRequired,
    #[error("bulk cover is required by config but cover flow is disabled")]
    CoverDisabledWhileRequired,
    #[error("bulk cover dial {0:?} does not require relay cover — misconfigured policy")]
    DialDoesNotRequireCover(SecurityDial),
}

/// Bulk cover-flow policy for a mix relay (spec §5.2 L2).
///
/// When [`Self::enabled`], production nodes must wire a cover outbound channel and
/// call [`crate::RelayHandle::begin_bulk_round`] (auto-started by [`crate::start_bulk_cover`]
/// / `aegis-node`). When [`Self::require`] is set, startup fails closed if cover cannot run.
///
/// ## Multi-hop defense (opt-in)
///
/// [`Self::multihop_defense`] selects wave A3/B1 productization of sim S4 rankings.
/// Default remains baseline local discard. Prefer
/// [`CoverMultihopDefense::MatchedLocalDiscard`] to align cover discard volume across
/// peer hops. [`CoverMultihopDefense::CoverOnions`] emits valid Sphinx peel-to-sink
/// onions when [`Self::cover_onion_terminal`] is set.
/// [`CoverMultihopDefense::CoverOnionsScaffold`] remains a tagged local-discard scaffold.
#[derive(Clone, Debug)]
pub struct BulkCoverConfig {
    /// When true, open L2 bulk rounds and emit cover padding at round close.
    pub enabled: bool,
    /// When true, refuse to run without cover channel + enabled cover policy.
    pub require: bool,
    /// Security dial for auto-started rounds (must be L2 when cover is required).
    pub dial: SecurityDial,
    /// Target observed flow count per bulk round.
    pub target_flow_count: u32,
    /// How often to close/re-open the bulk round so cover can emit (seconds).
    pub round_secs: u64,
    /// Multi-hop cover defense mode (default baseline local discard).
    pub multihop_defense: CoverMultihopDefense,
    /// Fixed cover flows per round under matched local discard (peer-aligned).
    pub matched_cover_flows: u32,
    /// Cover-onion flow count under cover_onions / cover_onions_scaffold.
    pub cover_onion_flows: u32,
    /// Terminal hop KEM public for peelable [`CoverMultihopDefense::CoverOnions`].
    pub cover_onion_terminal: Option<CoverOnionTerminal>,
}

impl Default for BulkCoverConfig {
    fn default() -> Self {
        Self {
            // Off by default so in-process unit tests that drive rounds manually stay unchanged.
            enabled: false,
            require: false,
            dial: SecurityDial::L2UniformBatched,
            target_flow_count: DEFAULT_COVER_TARGET_FLOW_COUNT,
            round_secs: DEFAULT_COVER_ROUND_SECS,
            multihop_defense: CoverMultihopDefense::BaselineLocalDiscard,
            matched_cover_flows: DEFAULT_MATCHED_COVER_FLOWS,
            cover_onion_flows: DEFAULT_COVER_ONION_FLOWS,
            cover_onion_terminal: None,
        }
    }
}

impl BulkCoverConfig {
    /// Production-oriented defaults: cover enabled and required.
    #[must_use]
    pub fn production() -> Self {
        Self {
            enabled: true,
            require: true,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn requirement(&self) -> CoverRequirement {
        l2_cover_requirement(self.target_flow_count)
    }

    /// Cover generator config derived from this policy.
    #[must_use]
    pub fn cover_flow_config(&self) -> CoverFlowConfig {
        CoverFlowConfig {
            cells_per_flow: aegis_crypto::fragment::SPHINX_FRAGMENT_COUNT,
            multihop_defense: self.multihop_defense,
            matched_cover_flows: self.matched_cover_flows,
            cover_onion_flows: self.cover_onion_flows,
            cover_onion_terminal: self.cover_onion_terminal.clone(),
        }
    }

    /// Attach the terminal hop used to build peelable cover onions.
    #[must_use]
    pub fn with_cover_onion_terminal(mut self, terminal: CoverOnionTerminal) -> Self {
        self.cover_onion_terminal = Some(terminal);
        self
    }

    /// Fail closed when cover is required but cannot be satisfied at spawn time.
    pub fn validate_spawn(&self, cover_channel_present: bool) -> Result<(), CoverPolicyError> {
        if !self.require {
            return Ok(());
        }
        if !self.enabled {
            return Err(CoverPolicyError::CoverDisabledWhileRequired);
        }
        if !cover_channel_present {
            return Err(CoverPolicyError::CoverChannelRequired);
        }
        if !dial_requires_relay_cover(self.dial) {
            return Err(CoverPolicyError::DialDoesNotRequireCover(self.dial));
        }
        Ok(())
    }
}

/// Per-relay configuration.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// Rate parameter μ for Exp(μ) per-hop mixing delay (mean delay = 1/μ).
    pub mu: f64,
    /// Bulk cover-flow policy (L2). Production nodes should use [`BulkCoverConfig::production`].
    pub bulk_cover: BulkCoverConfig,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            mu: DEFAULT_MU,
            bulk_cover: BulkCoverConfig::default(),
        }
    }
}

impl RelayConfig {
    pub fn new(mu: f64) -> Self {
        Self {
            mu,
            bulk_cover: BulkCoverConfig::default(),
        }
    }

    #[must_use]
    pub fn with_bulk_cover(mut self, bulk_cover: BulkCoverConfig) -> Self {
        self.bulk_cover = bulk_cover;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_negotiator::SecurityDial;

    #[test]
    fn production_policy_requires_cover_channel() {
        let policy = BulkCoverConfig::production();
        assert!(policy.enabled && policy.require);
        assert_eq!(
            policy.validate_spawn(false),
            Err(CoverPolicyError::CoverChannelRequired)
        );
        assert!(policy.validate_spawn(true).is_ok());
    }

    #[test]
    fn require_with_disabled_cover_fails() {
        let policy = BulkCoverConfig {
            enabled: false,
            require: true,
            ..BulkCoverConfig::default()
        };
        assert_eq!(
            policy.validate_spawn(true),
            Err(CoverPolicyError::CoverDisabledWhileRequired)
        );
    }

    #[test]
    fn non_l2_dial_rejected_when_required() {
        let policy = BulkCoverConfig {
            enabled: true,
            require: true,
            dial: SecurityDial::L0Raw,
            ..BulkCoverConfig::default()
        };
        assert_eq!(
            policy.validate_spawn(true),
            Err(CoverPolicyError::DialDoesNotRequireCover(
                SecurityDial::L0Raw
            ))
        );
    }

    #[test]
    fn cover_flow_config_carries_matched_defense() {
        let policy = BulkCoverConfig {
            multihop_defense: CoverMultihopDefense::MatchedLocalDiscard,
            matched_cover_flows: 4,
            ..BulkCoverConfig::default()
        };
        let cfg = policy.cover_flow_config();
        assert_eq!(
            cfg.multihop_defense,
            CoverMultihopDefense::MatchedLocalDiscard
        );
        assert_eq!(cfg.matched_cover_flows, 4);
        assert_eq!(cfg.matched_discard_cell_count(), 4 * cfg.cells_per_flow as u64);
    }
}
