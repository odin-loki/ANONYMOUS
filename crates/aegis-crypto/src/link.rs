//! Hop-to-hop link encryption: ChaCha20-Poly1305 AEAD. §2.1.
//!
//! Wraps each [`crate::cell::Cell`] (512 bytes) for the point-to-point link between
//! adjacent nodes. This is **separate** from the larger [`crate::sphinx::SphinxPacket`]
//! onion payload — a Sphinx packet may be fragmented or carried outside a single Cell
//! in later phases; here `seal`/`open` operate on the fixed 512-byte cell unit.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{CryptoRngCore, RngCore};

use crate::cell::{Cell, CELL_LEN};
use crate::{CryptoError, Result};

pub const LINK_NONCE_LEN: usize = 12;
pub const LINK_TAG_LEN: usize = 16;
/// On-wire frame: `nonce (12) || ciphertext (512) || tag (16)`.
pub const LINK_FRAME_LEN: usize = LINK_NONCE_LEN + CELL_LEN + LINK_TAG_LEN;

pub struct LinkKey([u8; 32]);

impl LinkKey {
    pub fn new(k: [u8; 32]) -> Self {
        LinkKey(k)
    }

    /// Seal a cell for transmission over the link.
    ///
    /// Returns `nonce || ciphertext || tag` (580 bytes).
    pub fn seal<R: RngCore + CryptoRngCore>(&self, cell: &Cell, rng: &mut R) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)
            .map_err(|_| CryptoError::Malformed("link key"))?;
        let mut nonce_bytes = [0u8; LINK_NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: cell.as_bytes(), aad: b"aegis-link-v1" })
            .map_err(|_| CryptoError::Malformed("seal"))?;
        debug_assert_eq!(ct.len(), CELL_LEN + LINK_TAG_LEN);
        let mut frame = Vec::with_capacity(LINK_FRAME_LEN);
        frame.extend_from_slice(&nonce_bytes);
        frame.extend_from_slice(&ct);
        Ok(frame)
    }

    /// Open a received link frame back into a [`Cell`].
    pub fn open(&self, frame: &[u8]) -> Result<Cell> {
        if frame.len() != LINK_FRAME_LEN {
            return Err(CryptoError::Malformed("link frame length"));
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&self.0)
            .map_err(|_| CryptoError::Malformed("link key"))?;
        let nonce = Nonce::from_slice(&frame[..LINK_NONCE_LEN]);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &frame[LINK_NONCE_LEN..],
                    aad: b"aegis-link-v1",
                },
            )
            .map_err(|_| CryptoError::IntegrityFailure)?;
        if pt.len() != CELL_LEN {
            return Err(CryptoError::Malformed("plaintext length"));
        }
        let mut cell_bytes = [0u8; CELL_LEN];
        cell_bytes.copy_from_slice(&pt);
        Ok(Cell(cell_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn seal_open_roundtrip() {
        let key = LinkKey::new([7u8; 32]);
        let cell = Cell::zeroed();
        let mut rng = OsRng;
        let frame = key.seal(&cell, &mut rng).unwrap();
        assert_eq!(frame.len(), LINK_FRAME_LEN);
        let opened = key.open(&frame).unwrap();
        assert_eq!(opened.as_bytes(), cell.as_bytes());
    }

    #[test]
    fn tampered_frame_rejected() {
        let key = LinkKey::new([9u8; 32]);
        let cell = Cell::zeroed();
        let mut rng = OsRng;
        let mut frame = key.seal(&cell, &mut rng).unwrap();
        frame[LINK_NONCE_LEN + 3] ^= 0x80;
        assert!(matches!(key.open(&frame), Err(CryptoError::IntegrityFailure)));
    }
}
