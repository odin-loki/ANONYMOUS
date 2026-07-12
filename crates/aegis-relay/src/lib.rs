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
//! ## In-process wiring
//!
//! Production transport (TCP/QUIC) is out of scope for Phase 3. Relays communicate
//! via `tokio::sync::mpsc` channels; see `tests/testnet.rs` for the e2e gate.

pub mod config;
pub mod delay;
pub mod node;
pub mod relay_id;

pub use config::{RelayConfig, DEFAULT_MU};
pub use delay::sample_mixing_delay;
pub use node::{packet_delta, ForwardedPacket, RelayHandle, RelayNode};
pub use relay_id::RelayId;
