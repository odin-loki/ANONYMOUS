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
//! [`cover_flow`] synthesizes [`aegis_crypto::cell::Command::SphinxFragment`] cell bursts
//! so observed bulk flow count reaches the negotiator target. Use
//! [`RelayHandle::begin_bulk_round`] / [`RelayHandle::end_bulk_round`] to open and close a
//! counting window; cover bursts are emitted on the optional cover outbound channel and
//! sealed by [`net::spawn_link_bridge`].
//!
//! ## TCP link bridge
//!
//! Real hop links are implemented in [`net`]: fixed-width AEAD frames over
//! `tokio::net::TcpStream`, with Sphinx fragmentation and per-connection
//! ephemeral handshake for link-layer forward secrecy.

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
    send_link_cell, send_sphinx_packet, write_packet, LinkBridgeConfig, LinkSession, NetError,
    PeerInfo, ExitSink, spawn_link_bridge, run_initiator_handshake, run_responder_handshake,
    DEFAULT_LINK_READ_TIMEOUT, DEFAULT_MAX_INBOUND_CONNECTIONS,
};
pub use node::{
    packet_delta, ForwardedPacket, RelayCoarseStats, RelayDebugStats, RelayHandle, RelayNode,
};
pub use relay_id::RelayId;
