//! Property-based parser fuzzing — equivalent attack surface to `fuzz/` libFuzzer targets.
//!
//! On Windows, `cargo-fuzz` binaries build with nightly but fail at runtime
//! (`STATUS_DLL_NOT_FOUND` for the MSVC sanitizer runtime). These tests exercise
//! the same malformed-input paths and are run in CI / local `cargo test`.

use aegis_crypto::cell::{Cell, CELL_LEN};
use aegis_crypto::fragment::{reassemble, SphinxReassembler, SPHINX_FRAGMENT_COUNT};
use aegis_crypto::kem::{KemHeader, RelayKemSecret, KEM_HEADER_LEN};
use aegis_crypto::link::{LinkKey, LINK_FRAME_LEN};
use aegis_crypto::replay::ReplayCache;
use aegis_crypto::sphinx::{process, SphinxPacket, SPHINX_PACKET_LEN};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        .. ProptestConfig::default()
    })]

    #[test]
    fn fuzz_sphinx_process_never_panics(data in prop::collection::vec(any::<u8>(), 0..=SPHINX_PACKET_LEN + 64)) {
        let mut bytes = [0u8; SPHINX_PACKET_LEN];
        let copy_len = data.len().min(SPHINX_PACKET_LEN);
        bytes[..copy_len].copy_from_slice(&data[..copy_len]);
        let packet = SphinxPacket::from_bytes(bytes);
        let (relay_sec, _) =
            RelayKemSecret::generate_deterministic([0x01; 32], [0x02; 32], [0x03; 32]);
        let mut replay = ReplayCache::with_capacity(256);
        let _ = process(&packet, &relay_sec, &mut replay);
    }

    #[test]
    fn fuzz_link_open_never_panics(data in prop::collection::vec(any::<u8>(), 0..=LINK_FRAME_LEN + 32)) {
        let key = LinkKey::new([0xAB; 32]);
        let mut frame = [0u8; LINK_FRAME_LEN];
        let copy_len = data.len().min(LINK_FRAME_LEN);
        frame[..copy_len].copy_from_slice(&data[..copy_len]);
        let _ = key.open(&frame);
        if !data.is_empty() {
            let short_len = data.len().min(LINK_FRAME_LEN.saturating_sub(1).max(1));
            let _ = key.open(&data[..short_len]);
        }
        if data.len() > LINK_FRAME_LEN {
            let _ = key.open(&data[..LINK_FRAME_LEN + 1]);
        }
    }

    #[test]
    fn fuzz_fragment_reassemble_never_panics(
        data in prop::collection::vec(any::<u8>(), 0..=CELL_LEN * (SPHINX_FRAGMENT_COUNT + 8))
    ) {
        let mut ras = SphinxReassembler::new();
        let max_cells = data.len() / CELL_LEN;
        for i in 0..max_cells.min(64) {
            let start = i * CELL_LEN;
            let mut buf = [0u8; CELL_LEN];
            buf.copy_from_slice(&data[start..start + CELL_LEN]);
            let cell = Cell::from_bytes(buf);
            let _ = ras.push(&cell);
        }

        if !data.is_empty() {
            let batch_len = (data.len() / CELL_LEN).min(SPHINX_FRAGMENT_COUNT + 4);
            let cells: Vec<Cell> = (0..batch_len)
                .map(|i| {
                    let start = i * CELL_LEN;
                    let mut buf = [0u8; CELL_LEN];
                    if start + CELL_LEN <= data.len() {
                        buf.copy_from_slice(&data[start..start + CELL_LEN]);
                    } else if start < data.len() {
                        let n = data.len() - start;
                        buf[..n].copy_from_slice(&data[start..]);
                    }
                    Cell::from_bytes(buf)
                })
                .collect();
            let _ = reassemble(&cells);
        }
    }

    #[test]
    fn fuzz_kem_decap_never_panics(data in prop::collection::vec(any::<u8>(), 0..=KEM_HEADER_LEN + 64)) {
        let (relay_sec, _) =
            RelayKemSecret::generate_deterministic([0x10; 32], [0x11; 32], [0x12; 32]);
        let _ = KemHeader::read_from(&data);
        let mut hdr_bytes = [0u8; KEM_HEADER_LEN];
        let n = data.len().min(KEM_HEADER_LEN);
        hdr_bytes[..n].copy_from_slice(&data[..n]);
        if let Ok(header) = KemHeader::read_from(&hdr_bytes) {
            let _ = relay_sec.decapsulate(&header);
        }
    }
}
