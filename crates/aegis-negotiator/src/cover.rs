//! Relay bulk loop-cover requirement (spec §5.2 L2, §5.3).
//!
//! L2 uniform+batched bulk needs constant **observed** flow-count per round so bulk
//! confirmation stays at baseline (~1/M). Relays synthesize cover flows to pad the
//! count; **this crate only computes how many cover flows are required** — actual
//! generation and injection is [`aegis-relay`]'s responsibility.

use crate::dial::SecurityDial;

/// Target observed flow count for a bulk round (held constant by relay cover).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverRequirement {
    pub target_flow_count: u32,
}

impl CoverRequirement {
    #[must_use]
    pub const fn new(target_flow_count: u32) -> Self {
        Self { target_flow_count }
    }
}

/// Additional relay-side cover flows needed so observed count reaches `target`.
///
/// Returns `0` when real participants already meet or exceed the target.
#[must_use]
pub const fn required_cover_flow_count(real_participants: usize, target: u32) -> u32 {
    target.saturating_sub(real_participants as u32)
}

impl CoverRequirement {
    /// Relay-side cover flows still needed for this round.
    #[must_use]
    pub fn cover_flows_needed(&self, real_participants: usize) -> u32 {
        required_cover_flow_count(real_participants, self.target_flow_count)
    }
}

/// Build an L2 cover requirement for a round targeting constant observed flow count.
#[must_use]
pub fn l2_cover_requirement(target_flow_count: u32) -> CoverRequirement {
    CoverRequirement::new(target_flow_count)
}

/// Whether the chosen dial expects a relay cover plan for this round.
#[must_use]
pub const fn dial_needs_cover_plan(dial: SecurityDial, real_participants: usize, target: u32) -> bool {
    matches!(dial, SecurityDial::L2UniformBatched)
        && required_cover_flow_count(real_participants, target) > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cover_flow_count_basic() {
        assert_eq!(required_cover_flow_count(3, 8), 5);
        assert_eq!(required_cover_flow_count(8, 8), 0);
        assert_eq!(required_cover_flow_count(10, 8), 0);
    }

    #[test]
    fn cover_requirement_struct() {
        let req = CoverRequirement::new(8);
        assert_eq!(req.cover_flows_needed(3), 5);
        assert_eq!(req.cover_flows_needed(8), 0);
    }

    #[test]
    fn l2_needs_cover_when_under_target() {
        assert!(dial_needs_cover_plan(
            SecurityDial::L2UniformBatched,
            3,
            8
        ));
        assert!(!dial_needs_cover_plan(
            SecurityDial::L2UniformBatched,
            8,
            8
        ));
        assert!(!dial_needs_cover_plan(SecurityDial::L0Raw, 1, 8));
    }
}
