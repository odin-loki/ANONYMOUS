//! # aegis-relay — Phase 3
//!
//! Mix relay: Sphinx process (via `aegis-crypto`), per-hop Exp(μ) mixing delay,
//! loop-cover accounting for active-attack detection, then forward. Delay is sized
//! only to let cover mix — it is **not** the security primitive (spec §4.4).
//!
//! See `docs/AEGIS_SPEC_v3_consolidated.md` §4.4 and the Phase gate in §10.
//!
//! ## Loop-cover accounting (minimal scope)
//!
//! [`RelayHandle::loop_return_count`] increments when `sphinx::process` returns
//! [`aegis_crypto::sphinx::Processed::LoopReturned`]. Full active-confirmation
//! detection logic is deferred to later phases; this crate only wires the counter.
//!
//! ## Bulk cover-flow padding (spec §5.2 L2, §5.3)
//!
//! [`cover_flow`] synthesizes `Command::Drop` cell bursts so observed bulk flow count
//! reaches the negotiator target. Use [`RelayHandle::begin_bulk_round`] /
//! [`RelayHandle::end_bulk_round`] to open and close a counting window.
//!
//! ## TCP link bridge
//!
//! Real hop links are implemented in [`net`]: fixed-width AEAD frames over
//! `tokio::net::TcpStream`, with Sphinx fragmentation. See that module's docs
//! for link-key provisioning limits (pre-shared keys; no handshake yet).

pub mod config;
pub mod cover_flow;
pub mod delay;
pub mod net;
pub mod node;
pub mod relay_id;

pub use config::{RelayConfig, DEFAULT_MU};
pub use cover_flow::{
    BulkRoundCommand, BulkRoundTracker, CoverEmitResult, CoverFlow, CoverFlowConfig,
    CoverFlowGenerator,
};
pub use delay::sample_mixing_delay;
pub use net::{
    send_sphinx_packet, write_packet, NetError, PeerInfo, ExitSink, spawn_link_bridge,
};
pub use node::{packet_delta, ForwardedPacket, RelayHandle, RelayNode};
pub use relay_id::RelayId;
