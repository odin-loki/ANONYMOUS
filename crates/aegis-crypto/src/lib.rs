//! # aegis-crypto — Phase 2: the Sphinx cryptographic core
//!
//! Implements the AEGIS wire format and per-hop cryptography. See
//! `docs/AEGIS_SPEC_v3_consolidated.md` §4.1 and §2.
//!
//! ## Security properties this module MUST provide (Phase-2 gate)
//! - **Constant size** for all packets regardless of path length.
//! - **Per-hop bitwise unlinkability** (a relay cannot link its input to output).
//! - **Integrity / tagging resistance** — any tamper randomizes the whole payload.
//! - **Replay protection** — per-epoch seen-tag cache rejects duplicates.
//! - **Post-quantum confidentiality** via the hybrid X25519 + ML-KEM-768 KEM.
//!
//! See `docs/AEGIS_phase2_implementation_notes.md` for the concrete packet layout,
//! primitive choices, and gate-property mapping.

pub mod cell;
pub mod kem;
pub mod replay;
pub mod sphinx;
pub mod link;
pub mod fragment;
#[cfg(feature = "noise-link")]
pub mod noise_link;

pub use kem::{
    blind_next, encapsulate, KemHeader, RelayKemPublic, RelayKemSecret, SharedSecret,
    KEM_HEADER_LEN, MLKEM768_CT_LEN,
};
pub use link::{
    derive_link_session_key, link_handshake_confirm_mac, link_handshake_finish_mac,
    link_handshake_init_write, link_handshake_resp_write, link_handshake_initiator_finish,
    link_handshake_responder_finish, parse_link_handshake_init, parse_link_handshake_mac,
    parse_link_handshake_resp, verify_link_handshake_confirm_mac, verify_link_handshake_finish_mac,
    LinkHandshakeBinding, LinkHandshakeInit, LinkHandshakeResp, LinkHandshakeTranscript, LinkKey,
    LINK_EPH_PUB_LEN, LINK_FRAME_LEN, LINK_HANDSHAKE_CONFIRM_LEN, LINK_HANDSHAKE_FINISH_LEN,
    LINK_HANDSHAKE_INIT_LEN, LINK_HANDSHAKE_MAC_LEN, LINK_HANDSHAKE_NONCE_LEN,
    LINK_HANDSHAKE_RESP_LEN, LINK_NONCE_LEN,
};
#[cfg(feature = "noise-link")]
pub use noise_link::{
    derive_noise_static_secret, noise_ik_initiator_read_msg2, noise_ik_initiator_write_msg1,
    noise_ik_responder_read_msg1, noise_static_public, verify_noise_static_public,
    NoiseIkInitiatorState, NoiseIkResponderState, NOISE_IK_MSG1_LEN, NOISE_IK_MSG2_LEN,
};
pub use replay::{
    ReplayCache, ReplayTag, DEFAULT_AUTO_ADVANCE_FILL_RATIO, DEFAULT_MAX_GENERATIONS,
    DEFAULT_REPLAY_CACHE_CAPACITY,
};
pub use fragment::{
    fragment, fragment_with_random_id, reassemble, FragmentError, PacketId, SphinxReassembler,
    FRAGMENT_HEADER_LEN, FRAGMENT_PAYLOAD_LEN, LAST_FRAGMENT_DATA_LEN, SPHINX_FRAGMENT_COUNT,
};
pub use sphinx::{
    build, process, process_cell, replay_tag, verify_mac, PathHop, Processed, SphinxPacket,
    ALPHA_LEN, BETA_LEN, DELTA_LEN, GAMMA_LEN, MAX_HOPS, ROUTING_SLOT_LEN, SPHINX_PACKET_LEN,
};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("integrity check failed (possible tagging attack)")]
    IntegrityFailure,
    #[error("replayed packet rejected")]
    Replay,
    #[error("malformed packet: {0}")]
    Malformed(&'static str),
    #[error("kem failure")]
    Kem,
}

pub type Result<T> = core::result::Result<T, CryptoError>;
