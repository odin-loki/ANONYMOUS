#![no_main]

//! Sphinx `process` crash harness (wave S1 / A6 deepen).
//! Pads/truncates to `SPHINX_PACKET_LEN`; fixed deterministic relay key.
//! Evidence: `scripts/run_sphinx_fuzz_evidence.sh` · overnight: `fuzz/README.md`.
//! Not a formal proof — panic/UB/crash search only.

use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::replay::ReplayCache;
use aegis_crypto::sphinx::{process, SphinxPacket, SPHINX_PACKET_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Always exercise the fixed-width packet path (zero-pad / truncate).
    let mut bytes = [0u8; SPHINX_PACKET_LEN];
    let copy_len = data.len().min(SPHINX_PACKET_LEN);
    if copy_len > 0 {
        bytes[..copy_len].copy_from_slice(&data[..copy_len]);
    }
    let packet = SphinxPacket::from_bytes(bytes);

    let (relay_sec, _) =
        RelayKemSecret::generate_deterministic([0x01; 32], [0x02; 32], [0x03; 32]);
    // Bounded cache keeps overnight RSS stable under duplicate-tag floods.
    let mut replay = ReplayCache::with_capacity(256);
    let _ = process(&packet, &relay_sec, &mut replay);

    // Second call with the same bytes stresses replay-cache insert / reject paths
    // without growing RSS (capacity capped).
    let _ = process(&packet, &relay_sec, &mut replay);
});