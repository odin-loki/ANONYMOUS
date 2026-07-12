//! Hop-to-hop link encryption: ChaCha20-Poly1305 AEAD. §2.1.
//!
//! Wraps each [`crate::cell::Cell`] (512 bytes) for the point-to-point link between
//! adjacent nodes. This is **separate** from the larger [`crate::sphinx::SphinxPacket`]
//! onion payload — a Sphinx packet may be fragmented or carried outside a single Cell
//! in later phases; here `seal`/`open` operate on the fixed 512-byte cell unit.
//!
//! ## Per-connection forward secrecy
//!
//! A lightweight handshake (`link_handshake_*`) runs once per TCP connection before
//! any AEAD frames. Ephemeral X25519 ECDH derives a fresh session key; the static
//! pre-shared key authenticates the exchange only (MAC binding over the transcript).

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{CryptoRngCore, RngCore};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::cell::{Cell, CELL_LEN};
use crate::{CryptoError, Result};

pub const LINK_NONCE_LEN: usize = 12;
pub const LINK_TAG_LEN: usize = 16;
/// On-wire frame: `nonce (12) || ciphertext (512) || tag (16)`.
pub const LINK_FRAME_LEN: usize = LINK_NONCE_LEN + CELL_LEN + LINK_TAG_LEN;

/// Ephemeral X25519 public key in the link handshake.
pub const LINK_EPH_PUB_LEN: usize = 32;
/// Fresh nonce per handshake role.
pub const LINK_HANDSHAKE_NONCE_LEN: usize = 16;
/// Keyed SHA3-256 MAC authenticating the handshake transcript.
pub const LINK_HANDSHAKE_MAC_LEN: usize = 32;

/// Initiator → responder: `eph_pk (32) || nonce (16)`.
pub const LINK_HANDSHAKE_INIT_LEN: usize = LINK_EPH_PUB_LEN + LINK_HANDSHAKE_NONCE_LEN;
/// Responder → initiator: `eph_pk (32) || nonce (16)`.
pub const LINK_HANDSHAKE_RESP_LEN: usize = LINK_EPH_PUB_LEN + LINK_HANDSHAKE_NONCE_LEN;
/// Initiator → responder: confirm MAC (32).
pub const LINK_HANDSHAKE_CONFIRM_LEN: usize = LINK_HANDSHAKE_MAC_LEN;
/// Responder → initiator: finish MAC (32).
pub const LINK_HANDSHAKE_FINISH_LEN: usize = LINK_HANDSHAKE_MAC_LEN;

const HANDSHAKE_AUTH_DOMAIN: &[u8] = b"aegis-link-handshake-auth-v1";
const HANDSHAKE_MAC_DOMAIN: &[u8] = b"aegis-link-handshake-mac-v1";
const HANDSHAKE_SESSION_DOMAIN: &[u8] = b"aegis-link-session-v1";
const HANDSHAKE_TRANSCRIPT_DOMAIN: &[u8] = b"aegis-link-handshake-v1";

const ROLE_INITIATOR: u8 = 0x01;
const ROLE_RESPONDER: u8 = 0x02;

use std::fmt;

pub struct LinkKey([u8; 32]);

impl fmt::Debug for LinkKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LinkKey([REDACTED])")
    }
}

impl LinkKey {
    pub fn new(k: [u8; 32]) -> Self {
        LinkKey(k)
    }

    /// Expose session key bytes for tests (zeroize after use in production callers).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Seal a cell for transmission over the link.
    ///
    /// Returns `nonce || ciphertext || tag` (580 bytes).
    pub fn seal<R: RngCore + CryptoRngCore>(&self, cell: &Cell, rng: &mut R) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)
            .map_err(|_| CryptoError::Malformed("link key"))?;
        let mut nonce_bytes = [0u8; LINK_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: cell.as_bytes(), aad: b"aegis-link-v1" })
            .map_err(|_| CryptoError::Malformed("seal"))?;
        debug_assert_eq!(ct.len(), CELL_LEN + LINK_TAG_LEN);
        let mut frame = Vec::with_capacity(LINK_FRAME_LEN);
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ct);
        Ok(frame)
    }

    /// Open a received link frame back into a [`Cell`].
    pub fn open(&self, frame: &[u8]) -> Result<Cell> {
        if frame.len() != LINK_FRAME_LEN {
            return Err(CryptoError::Malformed("link frame length"));
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)
            .map_err(|_| CryptoError::Malformed("link key"))?;
        let nonce = Nonce::from_slice(&frame[..LINK_NONCE_LEN]);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &frame[LINK_NONCE_LEN..],
                    aad: b"aegis-link-v1",
                },
            )
            .map_err(|_| CryptoError::IntegrityFailure)?;
        if pt.len() != CELL_LEN {
            return Err(CryptoError::Malformed("plaintext length"));
        }
        let mut cell_bytes = [0u8; CELL_LEN];
        cell_bytes.copy_from_slice(&pt);
        Ok(Cell(cell_bytes))
    }
}

impl PartialEq for LinkKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

/// Parsed initiator handshake message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkHandshakeInit {
    pub eph_pk: [u8; LINK_EPH_PUB_LEN],
    pub nonce: [u8; LINK_HANDSHAKE_NONCE_LEN],
}

/// Parsed responder handshake message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkHandshakeResp {
    pub eph_pk: [u8; LINK_EPH_PUB_LEN],
    pub nonce: [u8; LINK_HANDSHAKE_NONCE_LEN],
}

/// Binding transcript shared by both peers after init + resp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkHandshakeTranscript {
    pub initiator_eph_pk: [u8; LINK_EPH_PUB_LEN],
    pub initiator_nonce: [u8; LINK_HANDSHAKE_NONCE_LEN],
    pub responder_eph_pk: [u8; LINK_EPH_PUB_LEN],
    pub responder_nonce: [u8; LINK_HANDSHAKE_NONCE_LEN],
}

impl LinkHandshakeTranscript {
    pub fn from_messages(init: &LinkHandshakeInit, resp: &LinkHandshakeResp) -> Self {
        Self {
            initiator_eph_pk: init.eph_pk,
            initiator_nonce: init.nonce,
            responder_eph_pk: resp.eph_pk,
            responder_nonce: resp.nonce,
        }
    }
}

fn handshake_auth_key(psk: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(HANDSHAKE_AUTH_DOMAIN);
    h.update(psk);
    h.finalize().into()
}

fn handshake_mac(auth_key: &[u8; 32], role: u8, transcript: &LinkHandshakeTranscript) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(HANDSHAKE_MAC_DOMAIN);
    h.update(auth_key);
    h.update([role]);
    h.update(&transcript.initiator_eph_pk);
    h.update(&transcript.initiator_nonce);
    h.update(&transcript.responder_eph_pk);
    h.update(&transcript.responder_nonce);
    h.finalize().into()
}

fn verify_handshake_mac(
    auth_key: &[u8; 32],
    role: u8,
    transcript: &LinkHandshakeTranscript,
    mac: &[u8; LINK_HANDSHAKE_MAC_LEN],
) -> bool {
    let expected = handshake_mac(auth_key, role, transcript);
    bool::from(expected.ct_eq(mac))
}

fn derive_session_key_bytes(
    shared: &[u8; 32],
    transcript: &LinkHandshakeTranscript,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(HANDSHAKE_SESSION_DOMAIN);
    h.update(shared);
    h.update(HANDSHAKE_TRANSCRIPT_DOMAIN);
    h.update(&transcript.initiator_eph_pk);
    h.update(&transcript.initiator_nonce);
    h.update(&transcript.responder_eph_pk);
    h.update(&transcript.responder_nonce);
    h.finalize().into()
}

/// Generate initiator handshake message and retain the ephemeral secret locally.
pub fn link_handshake_init_write<R: RngCore + CryptoRngCore>(
    rng: &mut R,
) -> (EphemeralSecret, [u8; LINK_HANDSHAKE_INIT_LEN]) {
    let secret = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pk = PublicKey::from(&secret);
    let mut nonce = [0u8; LINK_HANDSHAKE_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let mut out = [0u8; LINK_HANDSHAKE_INIT_LEN];
    out[..LINK_EPH_PUB_LEN].copy_from_slice(eph_pk.as_bytes());
    out[LINK_EPH_PUB_LEN..].copy_from_slice(&nonce);
    (secret, out)
}

/// Parse initiator handshake bytes from the wire.
pub fn parse_link_handshake_init(bytes: &[u8]) -> Result<LinkHandshakeInit> {
    if bytes.len() != LINK_HANDSHAKE_INIT_LEN {
        return Err(CryptoError::Malformed("link handshake init length"));
    }
    let eph_pk = bytes[..LINK_EPH_PUB_LEN]
        .try_into()
        .map_err(|_| CryptoError::Malformed("link handshake init eph pk"))?;
    let nonce = bytes[LINK_EPH_PUB_LEN..]
        .try_into()
        .map_err(|_| CryptoError::Malformed("link handshake init nonce"))?;
    Ok(LinkHandshakeInit { eph_pk, nonce })
}

/// Generate responder handshake message.
pub fn link_handshake_resp_write<R: RngCore + CryptoRngCore>(
    rng: &mut R,
) -> (EphemeralSecret, [u8; LINK_HANDSHAKE_RESP_LEN]) {
    let secret = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pk = PublicKey::from(&secret);
    let mut nonce = [0u8; LINK_HANDSHAKE_NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let mut out = [0u8; LINK_HANDSHAKE_RESP_LEN];
    out[..LINK_EPH_PUB_LEN].copy_from_slice(eph_pk.as_bytes());
    out[LINK_EPH_PUB_LEN..].copy_from_slice(&nonce);
    (secret, out)
}

/// Parse responder handshake bytes from the wire.
pub fn parse_link_handshake_resp(bytes: &[u8]) -> Result<LinkHandshakeResp> {
    if bytes.len() != LINK_HANDSHAKE_RESP_LEN {
        return Err(CryptoError::Malformed("link handshake resp length"));
    }
    let eph_pk = bytes[..LINK_EPH_PUB_LEN]
        .try_into()
        .map_err(|_| CryptoError::Malformed("link handshake resp eph pk"))?;
    let nonce = bytes[LINK_EPH_PUB_LEN..]
        .try_into()
        .map_err(|_| CryptoError::Malformed("link handshake resp nonce"))?;
    Ok(LinkHandshakeResp { eph_pk, nonce })
}

/// Initiator confirm MAC (role = initiator).
pub fn link_handshake_confirm_mac(
    psk: &[u8; 32],
    transcript: &LinkHandshakeTranscript,
) -> [u8; LINK_HANDSHAKE_MAC_LEN] {
    let auth_key = handshake_auth_key(psk);
    handshake_mac(&auth_key, ROLE_INITIATOR, transcript)
}

/// Responder finish MAC (role = responder).
pub fn link_handshake_finish_mac(
    psk: &[u8; 32],
    transcript: &LinkHandshakeTranscript,
) -> [u8; LINK_HANDSHAKE_MAC_LEN] {
    let auth_key = handshake_auth_key(psk);
    handshake_mac(&auth_key, ROLE_RESPONDER, transcript)
}

/// Verify initiator confirm MAC with the expected PSK.
pub fn verify_link_handshake_confirm_mac(
    psk: &[u8; 32],
    transcript: &LinkHandshakeTranscript,
    mac: &[u8; LINK_HANDSHAKE_MAC_LEN],
) -> bool {
    let auth_key = handshake_auth_key(psk);
    verify_handshake_mac(&auth_key, ROLE_INITIATOR, transcript, mac)
}

/// Verify responder finish MAC with the expected PSK.
pub fn verify_link_handshake_finish_mac(
    psk: &[u8; 32],
    transcript: &LinkHandshakeTranscript,
    mac: &[u8; LINK_HANDSHAKE_MAC_LEN],
) -> bool {
    let auth_key = handshake_auth_key(psk);
    verify_handshake_mac(&auth_key, ROLE_RESPONDER, transcript, mac)
}

/// Parse a fixed-width handshake MAC from the wire.
pub fn parse_link_handshake_mac(bytes: &[u8]) -> Result<[u8; LINK_HANDSHAKE_MAC_LEN]> {
    if bytes.len() != LINK_HANDSHAKE_MAC_LEN {
        return Err(CryptoError::Malformed("link handshake mac length"));
    }
    bytes
        .try_into()
        .map_err(|_| CryptoError::Malformed("link handshake mac"))
}

/// Derive the per-connection AEAD key from ECDH and the handshake transcript.
pub fn derive_link_session_key(
    local_ephemeral: EphemeralSecret,
    peer_eph_pk: &[u8; LINK_EPH_PUB_LEN],
    transcript: &LinkHandshakeTranscript,
) -> LinkKey {
    let peer = PublicKey::from(*peer_eph_pk);
    let shared = local_ephemeral.diffie_hellman(&peer);
    let mut shared_bytes = *shared.as_bytes();
    let session = derive_session_key_bytes(&shared_bytes, transcript);
    shared_bytes.zeroize();
    LinkKey::new(session)
}

/// Complete initiator handshake given responder messages.
pub fn link_handshake_initiator_finish(
    psk: &[u8; 32],
    init_sk: EphemeralSecret,
    init: &LinkHandshakeInit,
    resp_msg: &[u8],
    finish_msg: &[u8],
) -> Result<(LinkKey, [u8; LINK_HANDSHAKE_CONFIRM_LEN])> {
    let resp = parse_link_handshake_resp(resp_msg)?;
    let transcript = LinkHandshakeTranscript::from_messages(init, &resp);
    let confirm = link_handshake_confirm_mac(psk, &transcript);
    let finish = parse_link_handshake_mac(finish_msg)?;
    if !verify_link_handshake_finish_mac(psk, &transcript, &finish) {
        return Err(CryptoError::IntegrityFailure);
    }
    let session = derive_link_session_key(init_sk, &resp.eph_pk, &transcript);
    Ok((session, confirm))
}

/// Complete responder handshake; returns session key if confirm MAC matches `psk`.
pub fn link_handshake_responder_finish(
    psk: &[u8; 32],
    resp_sk: EphemeralSecret,
    init: &LinkHandshakeInit,
    resp: &LinkHandshakeResp,
    confirm_msg: &[u8],
) -> Result<LinkKey> {
    let confirm = parse_link_handshake_mac(confirm_msg)?;
    let transcript = LinkHandshakeTranscript::from_messages(init, resp);
    if !verify_link_handshake_confirm_mac(psk, &transcript, &confirm) {
        return Err(CryptoError::IntegrityFailure);
    }
    Ok(derive_link_session_key(resp_sk, &init.eph_pk, &transcript))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn run_honest_handshake(psk: [u8; 32], rng: &mut OsRng) -> (LinkKey, LinkKey) {
        let (init_sk, init_msg) = link_handshake_init_write(rng);
        let init = parse_link_handshake_init(&init_msg).unwrap();
        let (resp_sk, resp_msg) = link_handshake_resp_write(rng);
        let resp = parse_link_handshake_resp(&resp_msg).unwrap();
        let transcript = LinkHandshakeTranscript::from_messages(&init, &resp);
        let confirm = link_handshake_confirm_mac(&psk, &transcript);
        let finish = link_handshake_finish_mac(&psk, &transcript);
        let key_i = link_handshake_initiator_finish(&psk, init_sk, &init, &resp_msg, &finish)
            .unwrap()
            .0;
        let key_r =
            link_handshake_responder_finish(&psk, resp_sk, &init, &resp, &confirm).unwrap();
        (key_i, key_r)
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = LinkKey::new([7u8; 32]);
        let cell = Cell::zeroed();
        let mut rng = OsRng;
        let frame = key.seal(&cell, &mut rng).unwrap();
        assert_eq!(frame.len(), LINK_FRAME_LEN);
        let opened = key.open(&frame).unwrap();
        assert_eq!(opened.as_bytes(), cell.as_bytes());
    }

    #[test]
    fn tampered_frame_rejected() {
        let key = LinkKey::new([9u8; 32]);
        let cell = Cell::zeroed();
        let mut rng = OsRng;
        let mut frame = key.seal(&cell, &mut rng).unwrap();
        frame[LINK_NONCE_LEN + 3] ^= 0x80;
        assert!(matches!(key.open(&frame), Err(CryptoError::IntegrityFailure)));
    }

    #[test]
    fn handshake_honest_parties_derive_matching_keys() {
        let psk = [0x42u8; 32];
        let mut rng = OsRng;
        let (key_i, key_r) = run_honest_handshake(psk, &mut rng);
        assert_eq!(key_i, key_r);
    }

    #[test]
    fn handshake_rejects_wrong_psk_on_responder() {
        let psk = [0x42u8; 32];
        let wrong = [0x43u8; 32];
        let mut rng = OsRng;
        let (init_sk, init_msg) = link_handshake_init_write(&mut rng);
        let init = parse_link_handshake_init(&init_msg).unwrap();
        let (resp_sk, resp_msg) = link_handshake_resp_write(&mut rng);
        let resp = parse_link_handshake_resp(&resp_msg).unwrap();
        let transcript = LinkHandshakeTranscript::from_messages(&init, &resp);
        let confirm = link_handshake_confirm_mac(&psk, &transcript);
        let finish = link_handshake_finish_mac(&psk, &transcript);
        let key_i =
            link_handshake_initiator_finish(&psk, init_sk, &init, &resp_msg, &finish).unwrap().0;
        let err = link_handshake_responder_finish(&wrong, resp_sk, &init, &resp, &confirm);
        assert!(matches!(err, Err(CryptoError::IntegrityFailure)));
        let _ = key_i;
    }

    #[test]
    fn handshake_rejects_wrong_psk_on_initiator_finish() {
        let psk = [0x42u8; 32];
        let wrong = [0x43u8; 32];
        let mut rng = OsRng;
        let (init_sk, init_msg) = link_handshake_init_write(&mut rng);
        let init = parse_link_handshake_init(&init_msg).unwrap();
        let (_resp_sk, resp_msg) = link_handshake_resp_write(&mut rng);
        let resp = parse_link_handshake_resp(&resp_msg).unwrap();
        let transcript = LinkHandshakeTranscript::from_messages(&init, &resp);
        let finish = link_handshake_finish_mac(&wrong, &transcript);
        let err = link_handshake_initiator_finish(&psk, init_sk, &init, &resp_msg, &finish);
        assert!(matches!(err, Err(CryptoError::IntegrityFailure)));
    }

    #[test]
    fn distinct_session_keys_per_connection() {
        let psk = [0x55u8; 32];
        let mut rng = OsRng;
        let (k1_i, _) = run_honest_handshake(psk, &mut rng);
        let (k2_i, _) = run_honest_handshake(psk, &mut rng);
        assert_ne!(k1_i, k2_i);
    }

    #[test]
    fn truncated_handshake_init_returns_err_not_panic() {
        let short = [0u8; LINK_HANDSHAKE_INIT_LEN - 1];
        assert!(parse_link_handshake_init(&short).is_err());
    }

    #[test]
    fn truncated_handshake_mac_returns_err_not_panic() {
        let short = [0u8; LINK_HANDSHAKE_MAC_LEN - 1];
        assert!(parse_link_handshake_mac(&short).is_err());
    }

    #[test]
    fn session_key_seals_after_handshake() {
        let psk = [0x11u8; 32];
        let mut rng = OsRng;
        let (key_i, key_r) = run_honest_handshake(psk, &mut rng);
        let cell = Cell::zeroed();
        let frame = key_i.seal(&cell, &mut rng).unwrap();
        let opened = key_r.open(&frame).unwrap();
        assert_eq!(opened.as_bytes(), cell.as_bytes());
    }
}
