//! Noise_IK hop-link mutual authentication via the [`snow`] crate.
//!
//! Uses standard **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** (BLAKE2s transcript,
//! ChaCha20-Poly1305, X25519). Wire sizes follow the Noise spec: **96-byte msg1**
//! (`e` ‖ enc(`s`) ‖ enc(payload tag)), **48-byte msg2** (`e` ‖ enc(payload tag)).
//! Session keys are derived from the Noise handshake hash with an AEGIS domain
//! separator; 580-byte cell AEAD framing is unchanged.
//!
//! Optional **`noise-link-legacy-sha3`**: exposes the pre-`snow` SHA3-256 transcript
//! in [`crate::noise_link_legacy`] (80-byte msg1; not byte-compatible with standard
//! Noise or this default path).
//!
//! Enabled by the `noise-link` feature.

use rand_core::{CryptoRngCore, RngCore};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::link::LinkKey;
use crate::{CryptoError, Result};

/// Initiator → responder: `e (32) || enc(s) (48) || enc(payload) tag (16)` = 96.
pub const NOISE_IK_MSG1_LEN: usize = 32 + 48 + 16;
/// Responder → initiator: `e (32) || enc() tag (16)`.
pub const NOISE_IK_MSG2_LEN: usize = 32 + 16;

const STATIC_SK_DOMAIN: &[u8] = b"aegis-noise-static-sk-v1";
const SESSION_DOMAIN: &[u8] = b"aegis-noise-session-v1";
const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Initiator state after sending message 1 (awaiting message 2).
pub struct NoiseIkInitiatorState {
    hs: snow::HandshakeState,
}

/// Write Noise_IK message 1. `remote_static_pk` must match the peer's roster expectation.
pub fn noise_ik_initiator_write_msg1<R: RngCore + CryptoRngCore>(
    local_static_secret: &[u8; 32],
    remote_static_pk: &[u8; 32],
    _rng: &mut R,
) -> Result<(NoiseIkInitiatorState, [u8; NOISE_IK_MSG1_LEN])> {
    let mut hs = snow::Builder::new(noise_params()?)
        .local_private_key(local_static_secret)
        .remote_public_key(remote_static_pk)
        .build_initiator()
        .map_err(map_snow_err)?;

    let mut msg = [0u8; NOISE_IK_MSG1_LEN];
    let len = hs.write_message(&[], &mut msg).map_err(map_snow_err)?;
    if len != NOISE_IK_MSG1_LEN {
        return Err(CryptoError::Malformed("noise msg1 length"));
    }

    Ok((NoiseIkInitiatorState { hs }, msg))
}

/// Finish initiator handshake after reading message 2.
pub fn noise_ik_initiator_read_msg2(
    mut state: NoiseIkInitiatorState,
    msg2: &[u8],
) -> Result<LinkKey> {
    if msg2.len() != NOISE_IK_MSG2_LEN {
        return Err(CryptoError::Malformed("noise msg2 length"));
    }
    let mut payload = [0u8; 64];
    state
        .hs
        .read_message(msg2, &mut payload)
        .map_err(map_snow_err)?;
    if !state.hs.is_handshake_finished() {
        return Err(CryptoError::Malformed("noise handshake incomplete"));
    }
    Ok(link_key_from_handshake_hash(state.hs.get_handshake_hash()))
}

/// Responder state after processing message 1 (ready to send message 2).
pub struct NoiseIkResponderState {
    /// Initiator static public key revealed (and AEAD-authenticated) in message 1.
    pub initiator_static_pk: [u8; 32],
    msg2: [u8; NOISE_IK_MSG2_LEN],
    session: LinkKey,
}

/// Process message 1 and produce message 2. Caller **must** verify
/// [`NoiseIkResponderState::initiator_static_pk`] against the roster before using the session.
pub fn noise_ik_responder_read_msg1<R: RngCore + CryptoRngCore>(
    local_static_secret: &[u8; 32],
    msg1: &[u8],
    _rng: &mut R,
) -> Result<NoiseIkResponderState> {
    if msg1.len() != NOISE_IK_MSG1_LEN {
        return Err(CryptoError::Malformed("noise msg1 length"));
    }

    let mut hs = snow::Builder::new(noise_params()?)
        .local_private_key(local_static_secret)
        .build_responder()
        .map_err(map_snow_err)?;

    let mut payload = [0u8; 64];
    hs.read_message(msg1, &mut payload)
        .map_err(map_snow_err)?;

    let remote = hs
        .get_remote_static()
        .ok_or(CryptoError::Malformed("noise initiator static missing"))?;
    if remote.len() != 32 {
        return Err(CryptoError::Malformed("noise initiator static length"));
    }
    let mut initiator_static_pk = [0u8; 32];
    initiator_static_pk.copy_from_slice(remote);

    let mut msg2 = [0u8; NOISE_IK_MSG2_LEN];
    let len = hs.write_message(&[], &mut msg2).map_err(map_snow_err)?;
    if len != NOISE_IK_MSG2_LEN {
        return Err(CryptoError::Malformed("noise msg2 length"));
    }
    if !hs.is_handshake_finished() {
        return Err(CryptoError::Malformed("noise handshake incomplete"));
    }

    let session = link_key_from_handshake_hash(hs.get_handshake_hash());

    Ok(NoiseIkResponderState {
        initiator_static_pk,
        msg2,
        session,
    })
}

impl NoiseIkResponderState {
    pub fn msg2(&self) -> &[u8; NOISE_IK_MSG2_LEN] {
        &self.msg2
    }

    /// Take the session key only after the caller has verified `initiator_static_pk`.
    pub fn into_session_if_peer_matches(self, expected_initiator_pk: &[u8; 32]) -> Result<LinkKey> {
        if !bool::from(self.initiator_static_pk.ct_eq(expected_initiator_pk)) {
            return Err(CryptoError::IntegrityFailure);
        }
        Ok(self.session)
    }
}

/// Derive a stable X25519 static secret from roster / PSK material (32 bytes).
pub fn derive_noise_static_secret(material: &[u8; 32]) -> [u8; 32] {
    use sha3::Digest;
    let mut h = Sha3_256::new();
    h.update(STATIC_SK_DOMAIN);
    h.update(material);
    h.finalize().into()
}

/// Public key bytes for a Noise static secret.
pub fn noise_static_public(static_secret: &[u8; 32]) -> [u8; 32] {
    let sk = StaticSecret::from(*static_secret);
    *PublicKey::from(&sk).as_bytes()
}

/// Constant-time check that `got` matches `expected`.
pub fn verify_noise_static_public(got: &[u8; 32], expected: &[u8; 32]) -> bool {
    bool::from(got.ct_eq(expected))
}

fn map_snow_err(err: snow::Error) -> CryptoError {
    match err {
        snow::Error::Decrypt => CryptoError::IntegrityFailure,
        _ => CryptoError::Malformed("noise handshake"),
    }
}

fn noise_params() -> Result<snow::params::NoiseParams> {
    NOISE_PATTERN
        .parse()
        .map_err(|_| CryptoError::Malformed("noise params"))
}

fn link_key_from_handshake_hash(h: &[u8]) -> LinkKey {
    use sha3::Digest;
    let mut d = Sha3_256::new();
    d.update(SESSION_DOMAIN);
    d.update(h);
    LinkKey::new(d.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn keypair_from_tag(tag: u8) -> ([u8; 32], [u8; 32]) {
        let mut material = [0u8; 32];
        material[0] = tag;
        material[1] = 0xA5;
        let sk = derive_noise_static_secret(&material);
        let pk = noise_static_public(&sk);
        (sk, pk)
    }

    #[test]
    fn noise_ik_honest_roundtrip_matching_keys() {
        let (init_sk, init_pk) = keypair_from_tag(1);
        let (resp_sk, resp_pk) = keypair_from_tag(2);
        let mut rng = OsRng;

        let (state, msg1) = noise_ik_initiator_write_msg1(&init_sk, &resp_pk, &mut rng).unwrap();
        let resp_state = noise_ik_responder_read_msg1(&resp_sk, &msg1, &mut rng).unwrap();
        assert!(verify_noise_static_public(
            &resp_state.initiator_static_pk,
            &init_pk
        ));
        let msg2 = *resp_state.msg2();
        let key_r = resp_state
            .into_session_if_peer_matches(&init_pk)
            .unwrap();
        let key_i = noise_ik_initiator_read_msg2(state, &msg2).unwrap();
        assert_eq!(key_i, key_r);
    }

    #[test]
    fn noise_ik_wrong_responder_static_fails() {
        let (init_sk, _) = keypair_from_tag(1);
        let (resp_sk, _) = keypair_from_tag(2);
        let (_, wrong_pk) = keypair_from_tag(9);
        let mut rng = OsRng;

        let (_state, msg1) =
            noise_ik_initiator_write_msg1(&init_sk, &wrong_pk, &mut rng).unwrap();
        let err = noise_ik_responder_read_msg1(&resp_sk, &msg1, &mut rng);
        assert!(matches!(err, Err(CryptoError::IntegrityFailure)));
    }

    #[test]
    fn noise_ik_wrong_initiator_static_rejected() {
        let (init_sk, init_pk) = keypair_from_tag(1);
        let (resp_sk, resp_pk) = keypair_from_tag(2);
        let (_, expected_other) = keypair_from_tag(3);
        let mut rng = OsRng;

        let (_state, msg1) =
            noise_ik_initiator_write_msg1(&init_sk, &resp_pk, &mut rng).unwrap();
        let resp_state = noise_ik_responder_read_msg1(&resp_sk, &msg1, &mut rng).unwrap();
        assert!(verify_noise_static_public(
            &resp_state.initiator_static_pk,
            &init_pk
        ));
        let err = resp_state.into_session_if_peer_matches(&expected_other);
        assert!(matches!(err, Err(CryptoError::IntegrityFailure)));
    }

    #[test]
    fn noise_ik_session_seals_cells() {
        use crate::cell::Cell;
        let (init_sk, init_pk) = keypair_from_tag(4);
        let (resp_sk, resp_pk) = keypair_from_tag(5);
        let mut rng = OsRng;
        let (state, msg1) = noise_ik_initiator_write_msg1(&init_sk, &resp_pk, &mut rng).unwrap();
        let resp_state = noise_ik_responder_read_msg1(&resp_sk, &msg1, &mut rng).unwrap();
        let msg2 = *resp_state.msg2();
        let key_r = resp_state.into_session_if_peer_matches(&init_pk).unwrap();
        let key_i = noise_ik_initiator_read_msg2(state, &msg2).unwrap();
        let cell = Cell::zeroed();
        let frame = key_i.seal(&cell, &mut rng).unwrap();
        assert_eq!(key_r.open(&frame).unwrap().as_bytes(), cell.as_bytes());
    }

    #[test]
    fn noise_ik_wire_sizes_match_spec() {
        let (init_sk, _) = keypair_from_tag(10);
        let (_, resp_pk) = keypair_from_tag(11);
        let mut rng = OsRng;
        let (_state, msg1) =
            noise_ik_initiator_write_msg1(&init_sk, &resp_pk, &mut rng).unwrap();
        assert_eq!(msg1.len(), NOISE_IK_MSG1_LEN);
        assert_eq!(NOISE_IK_MSG1_LEN, 96);
        let (resp_sk, _) = keypair_from_tag(11);
        let resp_state = noise_ik_responder_read_msg1(&resp_sk, &msg1, &mut rng).unwrap();
        assert_eq!(resp_state.msg2().len(), NOISE_IK_MSG2_LEN);
    }
}
