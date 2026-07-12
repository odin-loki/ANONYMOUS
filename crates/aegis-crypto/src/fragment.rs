//! Sphinx packet ↔ fixed-width [`crate::cell::Cell`] fragmentation.
//!
//! A [`crate::sphinx::SphinxPacket`] (8512 B) is too large for a single 512 B link
//! cell. This module splits every packet into a **fixed** number of same-size
//! cells so observers cannot fingerprint Sphinx traffic by fragment count or
//! per-fragment payload length.
//!
//! ## Wire layout (per cell)
//!
//! ```text
//! ┌─ command (1 B) ─┬─ frag_idx (1 B) ─┬─ packet_id (8 B) ─┬─ reserved (2 B) ─┬──── payload (500 B) ────┐
//! │ SphinxFragment  │ 0 .. COUNT-1     │ correlation id    │ 0x0000            │ fixed slot (padded tail) │
//! └─────────────────┴──────────────────┴───────────────────┴───────────────────┴──────────────────────────┘
//! CELL_LEN = 512; FRAGMENT_HEADER_LEN = 12; FRAGMENT_PAYLOAD_LEN = 500.
//! ```
//!
//! ## Fragment count arithmetic
//!
//! | Quantity | Value |
//! |----------|------:|
//! | `SPHINX_PACKET_LEN` | 8512 |
//! | `FRAGMENT_PAYLOAD_LEN` (`CELL_LEN - FRAGMENT_HEADER_LEN`) | 500 |
//! | `SPHINX_FRAGMENT_COUNT` (`ceil(8512 / 500)`) | **18** |
//! | Bytes in final fragment slot (`8512 - 17×500`) | 12 (+ 488 zero pad in slot) |
//!
//! Every emitted cell is exactly [`CELL_LEN`] bytes. The trailing fragment's unused
//! payload bytes are zero-padded; reassembly copies only the final 12 bytes of packet
//! data from that slot.
//!
//! ## Delivery order
//!
//! Reassembly assumes **in-order** delivery on a single logical link stream (the
//! same ordering guarantee already provided by TCP-style hop links). The caller
//! must not interleave fragments from different packets on one stream; use
//! distinct streams or complete one packet before starting the next. [`packet_id`]
//! is carried on the wire for future out-of-order collectors but is not required
//! for the in-order [`SphinxReassembler`].

use rand_core::{CryptoRngCore, RngCore};

use crate::cell::{Cell, Command, CELL_LEN};
use crate::sphinx::{SphinxPacket, SPHINX_PACKET_LEN};
use thiserror::Error;

/// Fixed header prefix inside each fragment cell's 512-byte body.
pub const FRAGMENT_HEADER_LEN: usize = 12;

/// Bytes of Sphinx packet data carried in each fragment's payload slot.
pub const FRAGMENT_PAYLOAD_LEN: usize = CELL_LEN - FRAGMENT_HEADER_LEN;

/// Every Sphinx packet occupies exactly this many link cells on the wire.
pub const SPHINX_FRAGMENT_COUNT: usize =
    ((SPHINX_PACKET_LEN - 1) / FRAGMENT_PAYLOAD_LEN) + 1;

/// Packet bytes placed in the last fragment slot (remainder after full slots).
pub const LAST_FRAGMENT_DATA_LEN: usize =
    SPHINX_PACKET_LEN - (SPHINX_FRAGMENT_COUNT - 1) * FRAGMENT_PAYLOAD_LEN;

const OFF_COMMAND: usize = 0;
const OFF_FRAG_IDX: usize = 1;
const OFF_PACKET_ID: usize = 2;
const OFF_RESERVED: usize = 10;
const OFF_PAYLOAD: usize = FRAGMENT_HEADER_LEN;

/// 8-byte correlation id stamped on every fragment of one Sphinx packet.
pub type PacketId = [u8; 8];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FragmentError {
    #[error("malformed fragment: {0}")]
    Malformed(&'static str),
    #[error("incomplete fragment set: expected {expected}, got {got}")]
    Incomplete { expected: usize, got: usize },
    #[error("fragment index out of order: expected {expected}, got {got}")]
    OutOfOrder { expected: u8, got: u8 },
    #[error("packet id mismatch")]
    PacketIdMismatch,
}

/// Split a Sphinx packet into exactly [`SPHINX_FRAGMENT_COUNT`] same-size cells.
pub fn fragment(packet: &SphinxPacket, packet_id: PacketId) -> [Cell; SPHINX_FRAGMENT_COUNT] {
    let bytes = packet.as_bytes();
    core::array::from_fn(|i| {
        let mut cell = Cell::zeroed();
        encode_fragment_cell(&mut cell, packet_id, i as u8, bytes);
        cell
    })
}

/// Split with a random [`PacketId`] (CSPRNG).
pub fn fragment_with_random_id<R: RngCore + CryptoRngCore>(
    packet: &SphinxPacket,
    rng: &mut R,
) -> ([Cell; SPHINX_FRAGMENT_COUNT], PacketId) {
    let mut packet_id = [0u8; 8];
    rng.fill_bytes(&mut packet_id);
    let cells = fragment(packet, packet_id);
    (cells, packet_id)
}

/// Reassemble an ordered fragment batch into the original Sphinx packet.
pub fn reassemble(cells: &[Cell]) -> Result<SphinxPacket, FragmentError> {
    if cells.len() != SPHINX_FRAGMENT_COUNT {
        return Err(FragmentError::Incomplete {
            expected: SPHINX_FRAGMENT_COUNT,
            got: cells.len(),
        });
    }
    let mut reassembler = SphinxReassembler::new();
    for cell in cells {
        if let Some(packet) = reassembler.push(cell)? {
            return Ok(packet);
        }
    }
    Err(FragmentError::Incomplete {
        expected: SPHINX_FRAGMENT_COUNT,
        got: cells.len(),
    })
}

/// Incremental in-order collector for one Sphinx packet at a time.
#[derive(Debug)]
pub struct SphinxReassembler {
    expected_index: u8,
    packet_id: Option<PacketId>,
    buf: [u8; SPHINX_PACKET_LEN],
}

impl Default for SphinxReassembler {
    fn default() -> Self {
        Self {
            expected_index: 0,
            packet_id: None,
            buf: [0u8; SPHINX_PACKET_LEN],
        }
    }
}

impl SphinxReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept the next fragment. Returns `Ok(Some(packet))` when complete.
    pub fn push(&mut self, cell: &Cell) -> Result<Option<SphinxPacket>, FragmentError> {
        let (packet_id, index, payload) = decode_fragment_cell(cell)?;

        if let Some(expected_id) = self.packet_id {
            if expected_id != packet_id {
                return Err(FragmentError::PacketIdMismatch);
            }
        } else {
            self.packet_id = Some(packet_id);
        }

        if index != self.expected_index {
            return Err(FragmentError::OutOfOrder {
                expected: self.expected_index,
                got: index,
            });
        }

        let dest_off = usize::from(index) * FRAGMENT_PAYLOAD_LEN;
        let copy_len = if usize::from(index) == SPHINX_FRAGMENT_COUNT - 1 {
            LAST_FRAGMENT_DATA_LEN
        } else {
            FRAGMENT_PAYLOAD_LEN
        };
        self.buf[dest_off..dest_off + copy_len].copy_from_slice(&payload[..copy_len]);

        self.expected_index += 1;
        if usize::from(self.expected_index) == SPHINX_FRAGMENT_COUNT {
            let packet = SphinxPacket::from_bytes(self.buf);
            self.reset();
            return Ok(Some(packet));
        }
        Ok(None)
    }

    pub fn reset(&mut self) {
        self.expected_index = 0;
        self.packet_id = None;
        self.buf = [0u8; SPHINX_PACKET_LEN];
    }
}

fn encode_fragment_cell(cell: &mut Cell, packet_id: PacketId, index: u8, packet: &[u8]) {
    let mut buf = [0u8; CELL_LEN];
    buf[OFF_COMMAND] = Command::SphinxFragment as u8;
    buf[OFF_FRAG_IDX] = index;
    buf[OFF_PACKET_ID..OFF_PACKET_ID + 8].copy_from_slice(&packet_id);
    // reserved [10..12] stays zero

    let src_off = usize::from(index) * FRAGMENT_PAYLOAD_LEN;
    let copy_len = if usize::from(index) == SPHINX_FRAGMENT_COUNT - 1 {
        LAST_FRAGMENT_DATA_LEN
    } else {
        FRAGMENT_PAYLOAD_LEN
    };
    buf[OFF_PAYLOAD..OFF_PAYLOAD + copy_len]
        .copy_from_slice(&packet[src_off..src_off + copy_len]);

    *cell = Cell::from_bytes(buf);
}

fn decode_fragment_cell(cell: &Cell) -> Result<(PacketId, u8, [u8; FRAGMENT_PAYLOAD_LEN]), FragmentError> {
    let b = cell.as_bytes();
    let cmd = Command::from_u8(b[OFF_COMMAND]).ok_or(FragmentError::Malformed("command"))?;
    if cmd != Command::SphinxFragment {
        return Err(FragmentError::Malformed("not a sphinx fragment"));
    }
    let index = b[OFF_FRAG_IDX];
    if usize::from(index) >= SPHINX_FRAGMENT_COUNT {
        return Err(FragmentError::Malformed("fragment index"));
    }
    if b[OFF_RESERVED..OFF_PAYLOAD] != [0u8; OFF_PAYLOAD - OFF_RESERVED] {
        return Err(FragmentError::Malformed("reserved bytes"));
    }
    let mut packet_id = [0u8; 8];
    packet_id.copy_from_slice(&b[OFF_PACKET_ID..OFF_PACKET_ID + 8]);
    let mut payload = [0u8; FRAGMENT_PAYLOAD_LEN];
    payload.copy_from_slice(&b[OFF_PAYLOAD..OFF_PAYLOAD + FRAGMENT_PAYLOAD_LEN]);
    Ok((packet_id, index, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::RelayKemSecret;
    use crate::sphinx::{build, PathHop, MAX_HOPS};
    use rand_core::OsRng;

    fn sample_path(n: usize) -> Vec<PathHop> {
        let mut rng = OsRng;
        let mut hops = Vec::new();
        for i in 0..n {
            let (_sec, pk) = RelayKemSecret::generate(&mut rng);
            let mut id = [0u8; 32];
            id[0] = i as u8;
            hops.push(PathHop { id, pk });
        }
        hops
    }

    fn round_trip(path_len: usize, payload: &[u8]) {
        let path = sample_path(path_len);
        let mut rng = OsRng;
        let packet = build(&path, payload, &mut rng).unwrap();
        let packet_id = [0xAA; 8];
        let cells = fragment(&packet, packet_id);
        for cell in &cells {
            assert_eq!(cell.as_bytes().len(), CELL_LEN);
        }
        let recovered = reassemble(&cells).unwrap();
        assert_eq!(recovered, packet);
    }

    #[test]
    fn round_trip_short_and_max_path() {
        round_trip(2, b"hi");
        round_trip(MAX_HOPS, &[0xCD; 64]);
    }

    #[test]
    fn round_trip_zero_payload() {
        round_trip(3, b"");
    }

    #[test]
    fn all_fragments_same_wire_size() {
        let path = sample_path(2);
        let mut rng = OsRng;
        let packet = build(&path, b"x", &mut rng).unwrap();
        let cells = fragment(&packet, [1; 8]);
        for (i, cell) in cells.iter().enumerate() {
            assert_eq!(cell.as_bytes().len(), CELL_LEN);
            assert_eq!(cell.as_bytes()[OFF_FRAG_IDX], i as u8);
            assert_eq!(
                cell.as_bytes()[OFF_COMMAND],
                Command::SphinxFragment as u8
            );
        }
    }

    #[test]
    fn incremental_reassembler_matches_batch() {
        let path = sample_path(4);
        let mut rng = OsRng;
        let packet = build(&path, b"incr", &mut rng).unwrap();
        let cells = fragment(&packet, [7; 8]);
        let mut ras = SphinxReassembler::new();
        let mut last = None;
        for cell in &cells {
            last = ras.push(cell).unwrap();
        }
        assert_eq!(last.unwrap(), packet);
    }

    #[test]
    fn truncated_set_errors() {
        let path = sample_path(2);
        let mut rng = OsRng;
        let packet = build(&path, b"t", &mut rng).unwrap();
        let cells = fragment(&packet, [0; 8]);
        let short = SPHINX_FRAGMENT_COUNT - 1;
        let err = reassemble(&cells[..short]).unwrap_err();
        assert!(matches!(
            err,
            FragmentError::Incomplete {
                expected: SPHINX_FRAGMENT_COUNT,
                got: _short
            } if _short == short
        ));
    }

    #[test]
    fn wrong_command_errors() {
        let mut cell = Cell::zeroed();
        cell.0[0] = Command::Data as u8;
        let err = SphinxReassembler::new().push(&cell).unwrap_err();
        assert!(matches!(err, FragmentError::Malformed(_)));
    }

    #[test]
    fn out_of_order_index_errors() {
        let path = sample_path(2);
        let mut rng = OsRng;
        let packet = build(&path, b"o", &mut rng).unwrap();
        let cells = fragment(&packet, [2; 8]);
        let mut ras = SphinxReassembler::new();
        let err = ras.push(&cells[1]).unwrap_err();
        assert!(matches!(
            err,
            FragmentError::OutOfOrder {
                expected: 0,
                got: 1
            }
        ));
    }

    #[test]
    fn packet_id_mismatch_errors() {
        let path = sample_path(2);
        let mut rng = OsRng;
        let packet = build(&path, b"id", &mut rng).unwrap();
        let mut cells = fragment(&packet, [1; 8]);
        cells[1].0[OFF_PACKET_ID] = 0xFF;
        let mut ras = SphinxReassembler::new();
        ras.push(&cells[0]).unwrap();
        let err = ras.push(&cells[1]).unwrap_err();
        assert_eq!(err, FragmentError::PacketIdMismatch);
    }

    #[test]
    fn fragment_count_constants() {
        assert_eq!(FRAGMENT_HEADER_LEN, 12);
        assert_eq!(FRAGMENT_PAYLOAD_LEN, 500);
        assert_eq!(SPHINX_FRAGMENT_COUNT, 18);
        assert_eq!(LAST_FRAGMENT_DATA_LEN, 12);
        assert_eq!(
            (SPHINX_FRAGMENT_COUNT - 1) * FRAGMENT_PAYLOAD_LEN + LAST_FRAGMENT_DATA_LEN,
            SPHINX_PACKET_LEN
        );
    }
}
