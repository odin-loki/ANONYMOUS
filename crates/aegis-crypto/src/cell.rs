//! Fixed-width 512-byte cell — the unit of transmission. §2.2.
//!
//! Every packet on every link is exactly `CELL_LEN` bytes so that payload size
//! never fingerprints traffic. This module is pure serialization (no secrets) and
//! is implemented in full.

pub const CELL_LEN: usize = 512;

/// Command byte identifying the cell's role on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Create = 0x01,
    Extend = 0x02,
    Data = 0x03,
    Drop = 0x04,       // dummy / cover cell — dropped inside the network
    LoopToSelf = 0x05, // client/mix loop cover (active-attack detection, §4.6/§5)
}

impl Command {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::Create,
            0x02 => Self::Extend,
            0x03 => Self::Data,
            0x04 => Self::Drop,
            0x05 => Self::LoopToSelf,
            _ => return None,
        })
    }
}

/// A serialized cell as it appears on the wire (opaque bytes).
#[derive(Clone)]
pub struct Cell(pub [u8; CELL_LEN]);

impl Cell {
    pub fn zeroed() -> Self {
        Cell([0u8; CELL_LEN])
    }
    pub fn as_bytes(&self) -> &[u8; CELL_LEN] {
        &self.0
    }
    pub fn from_bytes(b: [u8; CELL_LEN]) -> Self {
        Cell(b)
    }
}
