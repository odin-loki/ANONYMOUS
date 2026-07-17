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
//! `send(tick, cell)` each slot. Production egress uses [`TcpCellTransport`]
//! over a long-lived [`aegis_relay::LinkSession`]; tests use mock recorders.

pub mod driver;
pub mod emitter;
pub mod padding;
pub mod roster_load;
pub mod send;
pub mod session;
pub mod tcp_transport;
pub mod transport;

pub use driver::{config_with_tau_and_peak, config_with_tau_secs, run_emitter_loop};
pub use emitter::{
    env_allows_high_rho, rho_at_peak_rate, ConstantRateEmitter, EmitterConfig,
    DEFAULT_MAX_RHO, DEFAULT_PEAK_RATE_PER_SEC, MAX_CELL_PAYLOAD, DATA_HEADER_LEN,
    RhoLimitError,
};
pub use padding::{
    analyze_hard_cap, CountHardCapPadder, DeliverySlot, HardCapConfig, HardCapPadder,
    HardCapStats, RoundOutput,
};
pub use send::{
    build_packet, build_packet_require_bindings, build_packet_with_options, hops_from_bound_path,
    hops_from_keys, hops_from_keys_with_commitments, hops_from_records, send_payload_paced,
    send_payload_paced_default, BuildPacketOptions, ClientHop, ClientLink, SendError,
};
#[allow(deprecated)]
pub use send::{send_payload, send_payload_with_options};
pub use roster_load::{load_roster_from_config, RosterFileConfig, RosterLoadError};
pub use session::{PacedSession, PacedSessionConfig};
pub use tcp_transport::TcpCellTransport;
pub use transport::{ObserverRecord, OutboundCell, Transport};
