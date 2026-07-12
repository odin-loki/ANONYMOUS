#![no_main]

use aegis_crypto::kem::{KemHeader, RelayKemSecret, KEM_HEADER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (relay_sec, _) =
        RelayKemSecret::generate_deterministic([0x10; 32], [0x11; 32], [0x12; 32]);

    if data.len() < KEM_HEADER_LEN {
        let _ = KemHeader::read_from(data);
        return;
    }

    let mut hdr_bytes = [0u8; KEM_HEADER_LEN];
    let n = data.len().min(KEM_HEADER_LEN);
    hdr_bytes[..n].copy_from_slice(&data[..n]);
    if let Ok(header) = KemHeader::read_from(&hdr_bytes) {
        let _ = relay_sec.decapsulate(&header);
    }
});
