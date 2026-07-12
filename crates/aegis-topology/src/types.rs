//! Core identity and configuration types.

use std::fmt;

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

/// Metadata for a permissioned relay on the admission roster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayRecord {
    pub id: RelayId,
    pub jurisdiction: JurisdictionId,
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
