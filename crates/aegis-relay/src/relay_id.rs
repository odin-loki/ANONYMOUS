//! Local relay identity (32-byte address). Decoupled from `aegis-topology` to keep
//! this crate focused on per-hop processing; the wire format matches topology's
//! `RelayId([u8; 32])`.

/// A mix relay's stable identifier (same shape as `aegis_topology::RelayId`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct RelayId(pub [u8; 32]);

impl RelayId {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<[u8; 32]> for RelayId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<RelayId> for [u8; 32] {
    fn from(id: RelayId) -> Self {
        id.0
    }
}
