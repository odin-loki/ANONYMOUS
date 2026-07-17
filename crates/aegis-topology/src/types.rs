//! Core identity and configuration types.

use std::fmt;

use aegis_crypto::kem::{kem_public_commitment, RelayKemPublic};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Domain separation tag for [`RelayId::from_kem_commitment`].
pub const RELAY_ID_DOMAIN: &[u8] = b"aegis-relay-id-v1";

/// Stable relay identity.
///
/// **Production:** derive via [`RelayId::from_kem_commitment`] so the id binds to the
/// roster KEM public commitment. [`RelayId::from_u64`] is test/fixture only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RelayId(pub [u8; 32]);

impl RelayId {
    /// Test/fixture identity (not KEM-bound). Production rosters must use
    /// [`Self::from_kem_commitment`].
    pub fn from_u64(n: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        Self(bytes)
    }

    /// Derive `RelayId` as `SHA3-256(RELAY_ID_DOMAIN || commitment)`.
    ///
    /// Signed admission rejects records whose `id` does not match this digest when
    /// [`crate::roster::RosterAdmissionPolicy::require_kem_derived_id`] is set (default).
    pub fn from_kem_commitment(commitment: KemPublicCommitment) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(RELAY_ID_DOMAIN);
        hasher.update(commitment.0);
        Self(hasher.finalize().into())
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
    /// Build a roster record with an explicit id and KEM binding from a live public key.
    ///
    /// Prefer [`Self::from_kem_public`] in production so `id` is commitment-derived.
    pub fn new(id: RelayId, jurisdiction: JurisdictionId, kem_public: &RelayKemPublic) -> Self {
        Self {
            id,
            jurisdiction,
            kem_public_commitment: KemPublicCommitment::from_public(kem_public),
        }
    }

    /// Build a production-shaped record: id = [`RelayId::from_kem_commitment`].
    pub fn from_kem_public(jurisdiction: JurisdictionId, kem_public: &RelayKemPublic) -> Self {
        let kem_public_commitment = KemPublicCommitment::from_public(kem_public);
        Self {
            id: RelayId::from_kem_commitment(kem_public_commitment),
            jurisdiction,
            kem_public_commitment,
        }
    }

    /// Returns true when `pk` matches the KEM key committed at signed admission.
    pub fn binds_kem_public(&self, pk: &RelayKemPublic) -> bool {
        self.kem_public_commitment == KemPublicCommitment::from_public(pk)
    }

    /// Returns true when `id` equals [`RelayId::from_kem_commitment`] of the record commitment.
    pub fn id_matches_kem_commitment(&self) -> bool {
        self.id == RelayId::from_kem_commitment(self.kem_public_commitment)
    }
}

/// Deterministic hybrid KEM public key for tests and simulations.
pub fn test_kem_public_for_id(id: u64) -> RelayKemPublic {
    use aegis_crypto::kem::RelayKemSecret;

    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&id.to_le_bytes());
    RelayKemSecret::generate_deterministic(seed, seed, seed).1
}

/// KEM-derived [`RelayId`] for the deterministic test key of fixture `id`.
pub fn test_relay_id(id: u64) -> RelayId {
    RelayId::from_kem_commitment(KemPublicCommitment::from_public(&test_kem_public_for_id(id)))
}

/// Build a [`RelayRecord`] with deterministic test KEM binding and commitment-derived id.
pub fn test_relay_record(id: u64, jurisdiction: impl Into<String>) -> RelayRecord {
    RelayRecord::from_kem_public(JurisdictionId::new(jurisdiction), &test_kem_public_for_id(id))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_kem_commitment_is_stable_and_domain_separated() {
        let commitment = KemPublicCommitment([0xAB; 32]);
        let a = RelayId::from_kem_commitment(commitment);
        let b = RelayId::from_kem_commitment(commitment);
        assert_eq!(a, b);
        assert_ne!(a, RelayId(commitment.0), "id must not equal raw commitment bytes");
        assert_ne!(a, RelayId::from_u64(0));
    }

    #[test]
    fn test_relay_record_binds_id_to_commitment() {
        let record = test_relay_record(7, "US");
        assert!(record.id_matches_kem_commitment());
        assert_eq!(record.id, test_relay_id(7));
        assert!(record.binds_kem_public(&test_kem_public_for_id(7)));
    }
}
