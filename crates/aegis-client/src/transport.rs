//! Wire transport abstraction — decouples shaping logic from link I/O.
//!
//! Production egress uses [`crate::tcp_transport::TcpCellTransport`] over a
//! long-lived [`aegis_relay::LinkSession`]. Tests record observer-visible cadence
//! and size via mock implementations of this trait.

use aegis_crypto::cell::{Cell, CELL_LEN};

/// A fixed-size cell as it appears on the link layer (512 bytes).
///
/// Real and dummy cells are indistinguishable on the wire: same length, opaque bytes.
#[derive(Clone)]
pub struct OutboundCell(pub Cell);

impl OutboundCell {
    pub fn wire_len(&self) -> usize {
        CELL_LEN
    }

    pub fn as_bytes(&self) -> &[u8; CELL_LEN] {
        self.0.as_bytes()
    }
}

/// What a global passive adversary sees for one emission: cadence slot + size only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverRecord {
    pub tick: u64,
    pub size: usize,
}

/// Sends shaped cells onto the network.
///
/// Implementations may record observer-visible metadata for tests; they must not
/// expose real-vs-dummy distinctions through the observer API.
pub trait Transport {
    fn send(&mut self, tick: u64, cell: OutboundCell);
}
