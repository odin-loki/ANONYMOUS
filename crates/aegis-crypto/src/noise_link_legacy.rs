//! SHA3-256 transcript fallback for hop-link Noise_IK (pre-`snow` AEGIS wire).
//!
//! Enabled only with `noise-link-legacy-sha3`. **Not** byte-compatible with standard
//! `Noise_IK_25519_ChaChaPoly_BLAKE2s` or with the default `snow` path.

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

pub const NOISE_IK_MSG1_LEN: usize = 32 + 32 + 16;
pub const NOISE_IK_MSG2_LEN: usize = 32 + 16;

const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_SHA3_AEGIS_v1";
const EXTRACT_DOMAIN: &[u8] = b"aegis-noise-ik-extract-v1";
const EXPAND_CK_DOMAIN: &[u8] = b"aegis-noise-ik-expand-ck-v1";
const EXPAND_K_DOMAIN: &[u8] = b"aegis-noise-ik-expand-k-v1";
const SESSION_DOMAIN: &[u8] = b"aegis-noise-session-v1";

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

pub struct NoiseIkInitiatorState {
    ck: [u8; 32],
    h: [u8; 32],
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

pub fn noise_ik_initiator_write_msg1<R: RngCore + CryptoRngCore>(
    local_static_secret: &[u8; 32],
    remote_static_pk: &[u8; 32],
    rng: &mut R,
) -> Result<(NoiseIkInitiatorState, [u8; NOISE_IK_MSG1_LEN])> {
    let local_sk = StaticSecret::from(*local_static_secret);
    let local_pk = PublicKey::from(&local_sk);
    let remote_pk = PublicKey::from(*remote_static_pk);

    let (mut ck, mut h) = init_symmetric();
    mix_hash(&mut h, remote_pk.as_bytes());

    let mut eph_seed = [0u8; 32];
    rng.fill_bytes(&mut eph_seed);
    let eph_sk = StaticSecret::from(eph_seed);
    let eph_pk = PublicKey::from(&eph_sk);
    mix_hash(&mut h, eph_pk.as_bytes());

    let mut es = *eph_sk.diffie_hellman(&remote_pk).as_bytes();
    let k = mix_key(&mut ck, &es);
    es.zeroize();

    let enc_s = aead_encrypt(&k, 0, &h, local_pk.as_bytes())?;
    if enc_s.len() != 48 {
        return Err(CryptoError::Malformed("noise msg1 enc_s length"));
    }
    mix_hash(&mut h, &enc_s);

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

    let mut ee = *eph_sk.diffie_hellman(&e_r).as_bytes();
    let _k = mix_key(&mut state.ck, &ee);
    ee.zeroize();

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

pub struct NoiseIkResponderState {
    pub initiator_static_pk: [u8; 32],
    msg2: [u8; NOISE_IK_MSG2_LEN],
    session: LinkKey,
}

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

    let mut ss = *local_sk.diffie_hellman(&s_i).as_bytes();
    let _k = mix_key(&mut ck, &ss);
    ss.zeroize();

    let mut eph_seed = [0u8; 32];
    rng.fill_bytes(&mut eph_seed);
    let eph_sk = StaticSecret::from(eph_seed);
    eph_seed.zeroize();
    let eph_pk = PublicKey::from(&eph_sk);
    mix_hash(&mut h, eph_pk.as_bytes());

    let mut ee = *eph_sk.diffie_hellman(&e_i).as_bytes();
    let _k = mix_key(&mut ck, &ee);
    ee.zeroize();

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

    pub fn into_session_if_peer_matches(self, expected_initiator_pk: &[u8; 32]) -> Result<LinkKey> {
        if !bool::from(self.initiator_static_pk.ct_eq(expected_initiator_pk)) {
            return Err(CryptoError::IntegrityFailure);
        }
        Ok(self.session)
    }
}
