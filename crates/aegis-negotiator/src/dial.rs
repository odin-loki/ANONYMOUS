//! Security dial: L0 raw → L1 bucketed → L2 uniform+batched (spec §5.2).

/// Minimum concurrent bulk transfers for L2 to reach evidence-ledger baseline (~1/k).
pub const L2_BASELINE_CONCURRENCY: usize = 40;

/// Bulk-transfer security dial (spec §5.2). Ordered by increasing cost: L0 < L1 < L2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityDial {
    /// Near line rate; hides content + setup; **exposes** sender–receiver relationship.
    L0Raw,
    /// Size-bucketed + beacon-aligned rounds; partial relationship hiding (improves with concurrency).
    L1Bucketed,
    /// Uniform size + batched rounds + relay bulk loop-cover; full relationship hiding at k≈40.
    L2UniformBatched,
}

/// Stated threat requirement for a bulk transfer (negotiator input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreatLevel {
    /// Relationship exposure is acceptable (cheapest path).
    RelationshipExposureOk,
    /// Partial relationship hiding required (bucketed + aligned).
    PartialHidingRequired,
    /// Full relationship hiding required (uniform batched + relay cover).
    FullHidingRequired,
}

/// Numeric cost rank for dial ordering (lower = cheaper).
#[must_use]
pub const fn dial_cost(dial: SecurityDial) -> u8 {
    match dial {
        SecurityDial::L0Raw => 0,
        SecurityDial::L1Bucketed => 1,
        SecurityDial::L2UniformBatched => 2,
    }
}

/// Whether the dial structurally hides the sender–receiver relationship.
///
/// Matches evidence-ledger claims (§12): L0 → false; L1 → partial (treated as false
/// here); L2 → true (with relay cover and sufficient batch size).
#[must_use]
pub const fn dial_hides_relationship(dial: SecurityDial) -> bool {
    matches!(dial, SecurityDial::L2UniformBatched)
}

/// Whether the dial requires relay-side bulk loop-cover to hold observed flow-count constant.
#[must_use]
pub const fn dial_requires_relay_cover(dial: SecurityDial) -> bool {
    matches!(dial, SecurityDial::L2UniformBatched)
}

/// Pick the **minimum-cost** dial that meets the stated threat (spec §5.2).
///
/// `concurrency` is the expected number of independent bulk transfers in the same
/// beacon round (batch size). It does not change the minimum dial for a threat level
/// (full hiding always selects L2), but callers should ensure `concurrency >=
/// [`L2_BASELINE_CONCURRENCY`] when using L2 for evidence-ledger-grade hiding.
#[must_use]
pub const fn select_dial(threat: ThreatLevel, _concurrency: usize) -> SecurityDial {
    match threat {
        ThreatLevel::RelationshipExposureOk => SecurityDial::L0Raw,
        ThreatLevel::PartialHidingRequired => SecurityDial::L1Bucketed,
        ThreatLevel::FullHidingRequired => SecurityDial::L2UniformBatched,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dial_cost_ordering() {
        assert!(dial_cost(SecurityDial::L0Raw) < dial_cost(SecurityDial::L1Bucketed));
        assert!(dial_cost(SecurityDial::L1Bucketed) < dial_cost(SecurityDial::L2UniformBatched));
    }

    #[test]
    fn dial_hides_relationship_matches_ledger() {
        assert!(!dial_hides_relationship(SecurityDial::L0Raw));
        assert!(!dial_hides_relationship(SecurityDial::L1Bucketed));
        assert!(dial_hides_relationship(SecurityDial::L2UniformBatched));
    }

    #[test]
    fn only_l2_requires_relay_cover() {
        assert!(!dial_requires_relay_cover(SecurityDial::L0Raw));
        assert!(!dial_requires_relay_cover(SecurityDial::L1Bucketed));
        assert!(dial_requires_relay_cover(SecurityDial::L2UniformBatched));
    }

    #[test]
    fn select_dial_minimum_cost_table() {
        let cases = [
            (
                ThreatLevel::RelationshipExposureOk,
                1,
                SecurityDial::L0Raw,
            ),
            (
                ThreatLevel::RelationshipExposureOk,
                100,
                SecurityDial::L0Raw,
            ),
            (
                ThreatLevel::PartialHidingRequired,
                1,
                SecurityDial::L1Bucketed,
            ),
            (
                ThreatLevel::PartialHidingRequired,
                40,
                SecurityDial::L1Bucketed,
            ),
            (
                ThreatLevel::FullHidingRequired,
                1,
                SecurityDial::L2UniformBatched,
            ),
            (
                ThreatLevel::FullHidingRequired,
                L2_BASELINE_CONCURRENCY,
                SecurityDial::L2UniformBatched,
            ),
        ];
        for (threat, concurrency, expected) in cases {
            assert_eq!(
                select_dial(threat, concurrency),
                expected,
                "threat={threat:?} concurrency={concurrency}"
            );
        }
    }

    #[test]
    fn select_dial_is_minimum_meeting_threat() {
        for concurrency in [1usize, 5, 40, 200] {
            let d = select_dial(ThreatLevel::PartialHidingRequired, concurrency);
            assert!(dial_cost(d) >= dial_cost(SecurityDial::L1Bucketed));
            assert!(dial_cost(d) < dial_cost(SecurityDial::L2UniformBatched));
        }
    }
}
