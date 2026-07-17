//! Hybrid onion KEM: X25519 + ML-KEM-768. §2.1 / §4.1.
//!
//! # Design (Phase 2)
//!
//! Each hop's symmetric secret is derived as:
//!
//! ```text
//! secret = SHA3-256(ss_x25519 || ss_mlkem)
//! ```
//!
//! where `ss_x25519` comes from an ephemeral X25519 Diffie–Hellman with the relay's
//! long-term X25519 public key, and `ss_mlkem` from ML-KEM-768 encapsulation to the
//! relay's ML-KEM public key.
//!
//! The per-hop [`KemHeader`] (32-byte ephemeral X25519 public element + 1088-byte
//! ML-KEM-768 ciphertext) lives in the packet `alpha` region while the packet is in
//! transit. Subsequent hops' headers are onion-encrypted inside `beta` (see
//! `sphinx.rs`).
//!
//! [`blind_next`] implements classical Sphinx-style Montgomery-point blinding
//! (`P' = P · clamp(SHA3-256(secret))`) using `curve25519-dalek` (required because
//! `x25519-dalek` v2 does not re-export Montgomery arithmetic).

use curve25519_dalek::{montgomery::MontgomeryPoint, scalar::Scalar};
use kem_api::{Decapsulate, Encapsulate};
use ml_kem::{
    kem::DecapsulationKey, kem::EncapsulationKey, Ciphertext, EncodedSizeUser, KemCore, MlKem768,
};
use rand_core::CryptoRngCore;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::CryptoError;

/// ML-KEM-768 ciphertext length (FIPS 203).
pub const MLKEM768_CT_LEN: usize = 1088;

/// Serialized hybrid KEM header: X25519 element + ML-KEM ciphertext.
pub const KEM_HEADER_LEN: usize = 32 + MLKEM768_CT_LEN;

/// A derived per-hop symmetric secret. Zeroized on drop.
pub struct SharedSecret(pub [u8; 32]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Header material carried in the packet for a hop to run decapsulation.
#[derive(Clone)]
pub struct KemHeader {
    pub x25519_point: [u8; 32],
    pub mlkem_ct: [u8; MLKEM768_CT_LEN],
}

impl KemHeader {
    /// Serialize to a fixed `KEM_HEADER_LEN` byte slice.
    pub fn write_to(&self, out: &mut [u8]) {
        out[..32].copy_from_slice(&self.x25519_point);
        out[32..KEM_HEADER_LEN].copy_from_slice(&self.mlkem_ct);
    }

    /// Parse from a fixed `KEM_HEADER_LEN` byte slice.
    pub fn read_from(bytes: &[u8]) -> crate::Result<Self> {
        if bytes.len() < KEM_HEADER_LEN {
            return Err(CryptoError::Malformed("kem header too short"));
        }
        let mut mlkem_ct = [0u8; MLKEM768_CT_LEN];
        mlkem_ct.copy_from_slice(&bytes[32..KEM_HEADER_LEN]);
        Ok(Self {
            x25519_point: bytes[..32].try_into().expect("32"),
            mlkem_ct,
        })
    }
}

/// A relay's long-term KEM secret (X25519 scalar + ML-KEM decapsulation key).
pub struct RelayKemSecret {
    x25519: StaticSecret,
    mlkem: DecapsulationKey<ml_kem::MlKem768Params>,
}

/// Canonical prefix for hybrid relay KEM public-key bytes (X25519 || ML-KEM-768 EK).
pub const RELAY_KEM_CANONICAL_PREFIX: &[u8] = b"aegis-relay-kem-v1";

/// A relay's advertised KEM public key.
#[derive(Clone)]
pub struct RelayKemPublic {
    x25519: PublicKey,
    mlkem: EncapsulationKey<ml_kem::MlKem768Params>,
}

impl RelayKemPublic {
    /// Canonical encoding for roster admission binding (domain-separated).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mlkem_bytes = self.mlkem.as_bytes();
        let mut out = Vec::with_capacity(RELAY_KEM_CANONICAL_PREFIX.len() + 32 + mlkem_bytes.len());
        out.extend_from_slice(RELAY_KEM_CANONICAL_PREFIX);
        out.extend_from_slice(self.x25519.as_bytes());
        out.extend_from_slice(mlkem_bytes.as_ref());
        out
    }

    /// SHA3-256 commitment to [`Self::canonical_bytes`] for signed roster records.
    pub fn commitment(&self) -> [u8; 32] {
        kem_public_commitment(self)
    }
}

/// SHA3-256 commitment to a relay hybrid KEM public key.
pub fn kem_public_commitment(pk: &RelayKemPublic) -> [u8; 32] {
    Sha3_256::digest(pk.canonical_bytes()).into()
}

impl RelayKemSecret {
    /// Generate a fresh relay keypair.
    pub fn generate(rng: &mut impl CryptoRngCore) -> (Self, RelayKemPublic) {
        let x25519 = StaticSecret::random_from_rng(&mut *rng);
        let (mlkem, mlkem_pub) = MlKem768::generate(rng);
        let public = RelayKemPublic {
            x25519: PublicKey::from(&x25519),
            mlkem: mlkem_pub,
        };
        (Self { x25519, mlkem }, public)
    }

    /// Deterministic keypair for tests / KAT (seeded X25519 + ML-KEM `generate_deterministic`).
    pub fn generate_deterministic(
        x25519_seed: [u8; 32],
        mlkem_d: [u8; 32],
        mlkem_z: [u8; 32],
    ) -> (Self, RelayKemPublic) {
        let x25519 = StaticSecret::from(x25519_seed);
        let (mlkem, mlkem_pub) =
            MlKem768::generate_deterministic(&mlkem_d.into(), &mlkem_z.into());
        let public = RelayKemPublic {
            x25519: PublicKey::from(&x25519),
            mlkem: mlkem_pub,
        };
        (Self { x25519, mlkem }, public)
    }

    /// Decapsulate at a hop: derive the shared secret from the header.
    pub fn decapsulate(&self, header: &KemHeader) -> crate::Result<SharedSecret> {
        let peer = PublicKey::from(header.x25519_point);
        let ss_x = self.x25519.diffie_hellman(&peer);
        let ct = Ciphertext::<MlKem768>::try_from(header.mlkem_ct.as_slice())
            .map_err(|_| CryptoError::Malformed("ml-kem ct"))?;
        let ss_pq = Decapsulate::decapsulate(&self.mlkem, &ct).map_err(|_| CryptoError::Kem)?;
        Ok(hybrid_kdf(ss_x.as_bytes(), ss_pq.as_ref()))
    }
}

/// Client-side: encapsulate to a relay's public key, producing header + secret.
pub fn encapsulate(
    pk: &RelayKemPublic,
    rng: &mut impl CryptoRngCore,
) -> crate::Result<(KemHeader, SharedSecret)> {
    let ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
    let eph_pub = PublicKey::from(&ephemeral);
    let ss_x = ephemeral.diffie_hellman(&pk.x25519);
    let (ct, ss_pq) = Encapsulate::encapsulate(&pk.mlkem, rng).map_err(|_| CryptoError::Kem)?;
    let mut mlkem_ct = [0u8; MLKEM768_CT_LEN];
    mlkem_ct.copy_from_slice(ct.as_ref());
    let header = KemHeader {
        x25519_point: *eph_pub.as_bytes(),
        mlkem_ct,
    };
    Ok((header, hybrid_kdf(ss_x.as_bytes(), ss_pq.as_ref())))
}

/// Blind the X25519 group element for the next hop (Sphinx alpha-blinding).
pub fn blind_next(point: [u8; 32], secret: &SharedSecret) -> [u8; 32] {
    let scalar = blinding_scalar(secret);
    let blinded = MontgomeryPoint(point) * scalar;
    blinded.to_bytes()
}

fn hybrid_kdf(ss_x: &[u8], ss_pq: &[u8]) -> SharedSecret {
    let mut h = Sha3_256::new();
    h.update(ss_x);
    h.update(ss_pq);
    SharedSecret(h.finalize().into())
}

fn blinding_scalar(secret: &SharedSecret) -> Scalar {
    let digest = Sha3_256::digest(&secret.0);
    Scalar::from_bytes_mod_order(digest.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn mlkem_ct_len_matches_constant() {
        let mut rng = OsRng;
        let (_dk, ek) = MlKem768::generate(&mut rng);
        let (ct, _) = Encapsulate::encapsulate(&ek, &mut rng).unwrap();
        assert_eq!(ct.len(), MLKEM768_CT_LEN);
    }

    #[test]
    fn kem_public_commitment_is_stable() {
        let (_sk, pk) = RelayKemSecret::generate_deterministic([7u8; 32], [8u8; 32], [9u8; 32]);
        assert_eq!(pk.commitment(), kem_public_commitment(&pk));
        assert_ne!(pk.commitment(), kem_public_commitment(&RelayKemSecret::generate_deterministic([1u8; 32], [2u8; 32], [3u8; 32]).1));
    }
}
