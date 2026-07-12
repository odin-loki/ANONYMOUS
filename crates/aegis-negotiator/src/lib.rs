//! # aegis-negotiator — Phase 6
//!
//! Bulk plane: end-to-end negotiation over Mode 1 (protocol, not server), the security
//! DIAL (raw / bucketed / uniform+batched), rotating rendezvous, and the
//! batched-bulk-round scheduler that manufactures the bulk anonymity set. Relay bulk
//! loop-cover for confirmation resistance; enforce the F_max size ceiling.
//!
//! See `docs/AEGIS_SPEC_v3_consolidated.md` §5 and the Phase gate in §10.

pub mod ceiling;
pub mod cover;
pub mod dial;
pub mod rendezvous;
pub mod scheduler;

pub use ceiling::{
    enforce_ceiling, f_max, f_max_default, f_max_prose, fragment_sizes, BulkPlan,
    NegotiatorError, OverflowPolicy, DEFAULT_AVG_REAL, DEFAULT_C_FLOWS,
};
pub use cover::{
    required_cover_flow_count, CoverRequirement, dial_needs_cover_plan, l2_cover_requirement,
};
pub use dial::{
    dial_cost, dial_hides_relationship, dial_requires_relay_cover, select_dial, SecurityDial,
    ThreatLevel, L2_BASELINE_CONCURRENCY,
};
pub use rendezvous::{hamming_distance, rendezvous_id};
pub use scheduler::{next_round, BatchScheduler};
