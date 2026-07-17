//! Core identity and configuration types.

use std::fmt;

use aegis_crypto::kem::{kem_public_commitment, RelayKemPublic};
use serde::{Deserialize, Serialize};

/// Placeholder relay identity (future: public-key-derived from `aegis-crypto`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RelayId(pub [u8; 32]);

impl RelayId {
    pub fn from_u64(n: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        Self(bytes)
    }

    /// Raw 32-byte identity for [`aegis_trust::reputation::ReputationLedger`] lookups.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for RelayId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelayId({:02x}{:02x}…)", self.0[0], self.0[1])
    }
}

/// ISO-style jurisdiction label for diversity checks (e.g. `"US"`, `"DE"`).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JurisdictionId(pub String);

impl JurisdictionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl fmt::Debug for JurisdictionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JurisdictionId({:?})", self.0)
    }
}

/// SHA3-256 commitment to a relay's hybrid KEM public key at admission time.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KemPublicCommitment(pub [u8; 32]);

impl KemPublicCommitment {
    pub fn from_public(pk: &RelayKemPublic) -> Self {
        Self(kem_public_commitment(pk))
    }
}

impl fmt::Debug for KemPublicCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemPublicCommitment({:02x}{:02x}…)", self.0[0], self.0[1])
    }
}

/// Metadata for a permissioned relay on the admission roster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRecord {
    pub id: RelayId,
    pub jurisdiction: JurisdictionId,
    /// SHA3-256 commitment to the relay's long-term hybrid KEM public key.
    pub kem_public_commitment: KemPublicCommitment,
}

impl RelayRecord {
    /// Build a roster record with KEM binding from a live relay public key.
    pub fn new(id: RelayId, jurisdiction: JurisdictionId, kem_public: &RelayKemPublic) -> Self {
        Self {
            id,
            jurisdiction,
            kem_public_commitment: KemPublicCommitment::from_public(kem_public),
        }
    }

    /// Returns true when `pk` matches the KEM key committed at signed admission.
    pub fn binds_kem_public(&self, pk: &RelayKemPublic) -> bool {
        self.kem_public_commitment == KemPublicCommitment::from_public(pk)
    }
}

/// Deterministic hybrid KEM public key for tests and simulations.
pub fn test_kem_public_for_id(id: u64) -> RelayKemPublic {
    use aegis_crypto::kem::RelayKemSecret;

    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    RelayKemSecret::generate_deterministic(seed, seed, seed).1
}

/// Build a [`RelayRecord`] with deterministic test KEM binding for id `id`.
pub fn test_relay_record(id: u64, jurisdiction: impl Into<String>) -> RelayRecord {
    RelayRecord::new(
        RelayId::from_u64(id),
        JurisdictionId::new(jurisdiction),
        &test_kem_public_for_id(id),
    )
}

/// Stratified layer count and related topology parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TopologyConfig {
    /// Number of strata / hops (default 4 = high-threat per spec §4.5).
    pub layer_count: usize,
}

impl Default for TopologyConfig {
    fn default() -> Self {
        Self { layer_count: 4 }
    }
}

impl TopologyConfig {
    pub fn high_threat() -> Self {
        Self::default()
    }

    pub fn standard() -> Self {
        Self { layer_count: 3 }
    }
}
