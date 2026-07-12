#![no_main]

use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::replay::ReplayCache;
use aegis_crypto::sphinx::{process, SphinxPacket, SPHINX_PACKET_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut bytes = [0u8; SPHINX_PACKET_LEN];
    let copy_len = data.len().min(SPHINX_PACKET_LEN);
    bytes[..copy_len].copy_from_slice(&data[..copy_len]);
    let packet = SphinxPacket::from_bytes(bytes);

    let (relay_sec, _) =
        RelayKemSecret::generate_deterministic([0x01; 32], [0x02; 32], [0x03; 32]);
    let mut replay = ReplayCache::with_capacity(256);
    let _ = process(&packet, &relay_sec, &mut replay);
});
