//! Noise_IK-compatible hop-link mutual authentication.
//!
//! This is **not** a full [Noise Protocol](https://noiseprotocol.org) implementation:
//! the transcript follows the Noise_IK pattern (`-> e, es, s, ss` / `<- e, ee, se`)
//! with X25519 + ChaCha20-Poly1305, but uses SHA3-256 for mixing/HKDF instead of
//! BLAKE2s. Documented as a **Noise_IK-compatible transcript** for AEGIS hop links.
//!
//! Enabled by the `noise-link` feature.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{CryptoRngCore, RngCore};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::link::LinkKey;
use crate::{CryptoError, Result};

/// Initiator → responder: `e (32) || enc(s) (32) || tag (16)`.
pub const NOISE_IK_MSG1_LEN: usize = 32 + 32 + 16;
/// Responder → initiator: `e (32) || enc() (0) || tag (16)`.
pub const NOISE_IK_MSG2_LEN: usize = 32 + 16;

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_SHA3_AEGIS_v1";
const STATIC_SK_DOMAIN: &[u8] = b"aegis-noise-static-sk-v1";
const EXTRACT_DOMAIN: &[u8] = b"aegis-noise-ik-extract-v1";
const EXPAND_CK_DOMAIN: &[u8] = b"aegis-noise-ik-expand-ck-v1";
const EXPAND_K_DOMAIN: &[u8] = b"aegis-noise-ik-expand-k-v1";
const SESSION_DOMAIN: &[u8] = b"aegis-noise-session-v1";

/// Derive a stable X25519 static secret from roster / PSK material (32 bytes).
pub fn derive_noise_static_secret(material: &[u8; 32]) -> [u8; 32] {
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

fn mix_hash(h: &mut [u8; 32], data: &[u8]) {
    let mut d = Sha3_256::new();
    d.update(&*h);
    d.update(data);
    *h = d.finalize().into();
}

fn hkdf(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut extract = Sha3_256::new();
    extract.update(EXTRACT_DOMAIN);
    extract.update(ck);
    extract.update(ikm);
    let temp: [u8; 32] = extract.finalize().into();

    let mut ck_h = Sha3_256::new();
    ck_h.update(EXPAND_CK_DOMAIN);
    ck_h.update(&temp);
    let new_ck: [u8; 32] = ck_h.finalize().into();

    let mut k_h = Sha3_256::new();
    k_h.update(EXPAND_K_DOMAIN);
    k_h.update(&temp);
    let k: [u8; 32] = k_h.finalize().into();
    (new_ck, k)
}

fn aead_nonce(n: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&n.to_le_bytes());
    *Nonce::from_slice(&bytes)
}

fn aead_encrypt(key: &[u8; 32], n: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::Malformed("noise aead key"))?;
    cipher
        .encrypt(
            &aead_nonce(n),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Malformed("noise encrypt"))
}

fn aead_decrypt(key: &[u8; 32], n: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| CryptoError::Malformed("noise aead key"))?;
    cipher
        .decrypt(
            &aead_nonce(n),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::IntegrityFailure)
}

fn init_symmetric() -> ([u8; 32], [u8; 32]) {
    let mut h = Sha3_256::new();
    h.update(PROTOCOL_NAME);
    let hash: [u8; 32] = h.finalize().into();
    (hash, hash)
}

fn mix_key(ck: &mut [u8; 32], dh_out: &[u8; 32]) -> [u8; 32] {
    let (new_ck, k) = hkdf(ck, dh_out);
    *ck = new_ck;
    k
}

fn split_session(ck: &[u8; 32], h: &[u8; 32]) -> LinkKey {
    let mut d = Sha3_256::new();
    d.update(SESSION_DOMAIN);
    d.update(ck);
    d.update(h);
    LinkKey::new(d.finalize().into())
}

/// Initiator state after sending message 1 (awaiting message 2).
pub struct NoiseIkInitiatorState {
    ck: [u8; 32],
    h: [u8; 32],
    /// Ephemeral static-secret seed (reusable for multiple DHs).
    eph_seed: [u8; 32],
    local_static: [u8; 32],
}

impl Drop for NoiseIkInitiatorState {
    fn drop(&mut self) {
        self.ck.zeroize();
        self.h.zeroize();
        self.eph_seed.zeroize();
        self.local_static.zeroize();
    }
}

/// Write Noise_IK message 1. `remote_static_pk` must match the peer's roster expectation.
pub fn noise_ik_initiator_write_msg1<R: RngCore + CryptoRngCore>(
    local_static_secret: &[u8; 32],
    remote_static_pk: &[u8; 32],
    rng: &mut R,
) -> Result<(NoiseIkInitiatorState, [u8; NOISE_IK_MSG1_LEN])> {
    let local_sk = StaticSecret::from(*local_static_secret);
    let local_pk = PublicKey::from(&local_sk);
    let remote_pk = PublicKey::from(*remote_static_pk);

    let (mut ck, mut h) = init_symmetric();
    // Pre-message: responder static
    mix_hash(&mut h, remote_pk.as_bytes());

    let mut eph_seed = [0u8; 32];
    rng.fill_bytes(&mut eph_seed);
    let eph_sk = StaticSecret::from(eph_seed);
    let eph_pk = PublicKey::from(&eph_sk);
    mix_hash(&mut h, eph_pk.as_bytes());

    // es = DH(e_i, s_r)
    let mut es = *eph_sk.diffie_hellman(&remote_pk).as_bytes();
    let k = mix_key(&mut ck, &es);
    es.zeroize();

    let enc_s = aead_encrypt(&k, 0, &h, local_pk.as_bytes())?;
    if enc_s.len() != 48 {
        return Err(CryptoError::Malformed("noise msg1 enc_s length"));
    }
    mix_hash(&mut h, &enc_s);

    // ss = DH(s_i, s_r)
    let mut ss = *local_sk.diffie_hellman(&remote_pk).as_bytes();
    let _k = mix_key(&mut ck, &ss);
    ss.zeroize();

    let mut msg = [0u8; NOISE_IK_MSG1_LEN];
    msg[..32].copy_from_slice(eph_pk.as_bytes());
    msg[32..].copy_from_slice(&enc_s);

    Ok((
        NoiseIkInitiatorState {
            ck,
            h,
            eph_seed,
            local_static: *local_static_secret,
        },
        msg,
    ))
}

/// Finish initiator handshake after reading message 2.
pub fn noise_ik_initiator_read_msg2(
    mut state: NoiseIkInitiatorState,
    msg2: &[u8],
) -> Result<LinkKey> {
    if msg2.len() != NOISE_IK_MSG2_LEN {
        return Err(CryptoError::Malformed("noise msg2 length"));
    }
    let e_r = PublicKey::from(
        <[u8; 32]>::try_from(&msg2[..32]).map_err(|_| CryptoError::Malformed("noise msg2 e"))?,
    );
    let enc = &msg2[32..];

    let eph_sk = StaticSecret::from(state.eph_seed);
    let local_sk = StaticSecret::from(state.local_static);

    mix_hash(&mut state.h, e_r.as_bytes());

    // ee = DH(e_i, e_r)
    let mut ee = *eph_sk.diffie_hellman(&e_r).as_bytes();
    let _k = mix_key(&mut state.ck, &ee);
    ee.zeroize();

    // se = DH(s_i, e_r)
    let mut se = *local_sk.diffie_hellman(&e_r).as_bytes();
    let k = mix_key(&mut state.ck, &se);
    se.zeroize();

    let pt = aead_decrypt(&k, 0, &state.h, enc)?;
    if !pt.is_empty() {
        return Err(CryptoError::Malformed("noise msg2 payload"));
    }
    mix_hash(&mut state.h, enc);

    Ok(split_session(&state.ck, &state.h))
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
    rng: &mut R,
) -> Result<NoiseIkResponderState> {
    if msg1.len() != NOISE_IK_MSG1_LEN {
        return Err(CryptoError::Malformed("noise msg1 length"));
    }
    let local_sk = StaticSecret::from(*local_static_secret);
    let local_pk = PublicKey::from(&local_sk);

    let e_i = PublicKey::from(
        <[u8; 32]>::try_from(&msg1[..32]).map_err(|_| CryptoError::Malformed("noise msg1 e"))?,
    );
    let enc_s = &msg1[32..];

    let (mut ck, mut h) = init_symmetric();
    mix_hash(&mut h, local_pk.as_bytes());
    mix_hash(&mut h, e_i.as_bytes());

    // es = DH(s_r, e_i)
    let mut es = *local_sk.diffie_hellman(&e_i).as_bytes();
    let k = mix_key(&mut ck, &es);
    es.zeroize();

    let s_i_bytes = aead_decrypt(&k, 0, &h, enc_s)?;
    if s_i_bytes.len() != 32 {
        return Err(CryptoError::Malformed("noise initiator static length"));
    }
    let mut initiator_static_pk = [0u8; 32];
    initiator_static_pk.copy_from_slice(&s_i_bytes);
    mix_hash(&mut h, enc_s);

    let s_i = PublicKey::from(initiator_static_pk);

    // ss = DH(s_r, s_i)
    let mut ss = *local_sk.diffie_hellman(&s_i).as_bytes();
    let _k = mix_key(&mut ck, &ss);
    ss.zeroize();

    let mut eph_seed = [0u8; 32];
    rng.fill_bytes(&mut eph_seed);
    let eph_sk = StaticSecret::from(eph_seed);
    eph_seed.zeroize();
    let eph_pk = PublicKey::from(&eph_sk);
    mix_hash(&mut h, eph_pk.as_bytes());

    // ee = DH(e_r, e_i)
    let mut ee = *eph_sk.diffie_hellman(&e_i).as_bytes();
    let _k = mix_key(&mut ck, &ee);
    ee.zeroize();

    // se = DH(e_r, s_i)
    let mut se = *eph_sk.diffie_hellman(&s_i).as_bytes();
    let k = mix_key(&mut ck, &se);
    se.zeroize();

    let enc = aead_encrypt(&k, 0, &h, b"")?;
    if enc.len() != 16 {
        return Err(CryptoError::Malformed("noise msg2 enc length"));
    }
    mix_hash(&mut h, &enc);

    let mut msg2 = [0u8; NOISE_IK_MSG2_LEN];
    msg2[..32].copy_from_slice(eph_pk.as_bytes());
    msg2[32..].copy_from_slice(&enc);

    let session = split_session(&ck, &h);
    ck.zeroize();
    h.zeroize();

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

/// Constant-time check that `got` matches `expected`.
pub fn verify_noise_static_public(got: &[u8; 32], expected: &[u8; 32]) -> bool {
    bool::from(got.ct_eq(expected))
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
}
