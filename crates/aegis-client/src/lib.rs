//! # aegis-client — Phase 4
//!
//! Constant-rate emitter (one cell per slot τ, real-or-dummy; keep ρ ≤ 0.7) and
//! hard-cap receiver padding (observable = exactly Q every round, defer excess;
//! Q ≥ ~1.2× sustained mean). This crate is the make-or-break Mode-1 client core.
//!
//! See `docs/AEGIS_SPEC_v3_consolidated.md` §4.2, §4.3 and the Phase gate in §10.
//!
//! ## Transport decoupling
//!
//! Sending onto the mixnet is modeled by [`Transport`]: the emitter calls
//! `send(tick, cell)` each slot. Phase 4 tests use a mock that records only
//! observer-visible cadence and size. Wiring to [`aegis-relay`] is deliberate
//! out-of-scope integration work for a later phase.
//!
//! [`aegis-relay`]: ../aegis-relay

pub mod driver;
pub mod emitter;
pub mod padding;
pub mod transport;

pub use driver::{config_with_tau_secs, run_emitter_loop};
pub use emitter::{
    ConstantRateEmitter, EmitterConfig, MAX_CELL_PAYLOAD, DATA_HEADER_LEN,
};
pub use padding::{
    analyze_hard_cap, CountHardCapPadder, DeliverySlot, HardCapConfig, HardCapPadder,
    HardCapStats, RoundOutput,
};
pub use transport::{ObserverRecord, OutboundCell, Transport};
