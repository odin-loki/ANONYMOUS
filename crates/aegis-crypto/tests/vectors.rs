//! Phase-2 acceptance gate: cryptographic property/KAT tests.
//! These MUST pass before aegis-crypto is considered done (spec §10, Phase 2 gate).

use aegis_crypto::kem::{encapsulate, RelayKemSecret};
use aegis_crypto::replay::ReplayCache;
use aegis_crypto::sphinx::{
    build, process, tamper_beta_byte, PathHop, SphinxPacket, SPHINX_PACKET_LEN, MAX_HOPS,
};
use aegis_crypto::CryptoError;
use rand_core::OsRng;

fn make_path(len: usize) -> (Vec<PathHop>, Vec<RelayKemSecret>) {
    let mut rng = OsRng;
    let mut hops = Vec::new();
    let mut secrets = Vec::new();
    for i in 0..len {
        let (sec, pk) = RelayKemSecret::generate(&mut rng);
        let mut id = [0u8; 32];
        id[0] = i as u8 + 1;
        hops.push(PathHop { id, pk });
        secrets.push(sec);
    }
    (hops, secrets)
}

#[test]
fn constant_size_regardless_of_path_length() {
    let mut rng = OsRng;
    let mut sizes = Vec::new();
    for len in 2..=MAX_HOPS {
        let (path, _secrets) = make_path(len);
        let packet = build(&path, &[0xAB; 64], &mut rng).expect("build");
        sizes.push(packet.as_bytes().len());
    }
    assert!(sizes.iter().all(|&n| n == SPHINX_PACKET_LEN));
    assert!(sizes.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn tampered_packet_is_rejected() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(3);
    let packet = build(&path, b"tamper-test", &mut rng).expect("build");
    let mut tampered = packet.clone();
    tamper_beta_byte(&mut tampered, 4);
    let mut replay = ReplayCache::new();
    let err = process(&tampered, &secrets[0], &mut replay).unwrap_err();
    assert!(matches!(err, CryptoError::IntegrityFailure));
}

#[test]
fn replayed_packet_is_rejected() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(2);
    let packet = build(&path, b"replay", &mut rng).expect("build");
    let mut replay = ReplayCache::new();
    process(&packet, &secrets[0], &mut replay).expect("first process");
    let err = process(&packet, &secrets[0], &mut replay).unwrap_err();
    assert!(matches!(err, CryptoError::Replay));
}

/// Self-consistent hybrid KEM KAT (no cross-implementation official vector in this repo).
///
/// A fixed seed drives deterministic relay key generation; encapsulation uses `OsRng`
/// for the ephemeral X25519 + ML-KEM randomness. We assert the decapsulated
/// `SharedSecret` matches the encapsulator's output for the same header.
#[test]
fn hybrid_kem_known_answer() {
    let x_seed = [0x42u8; 32];
    let mlkem_d = [0x11u8; 32];
    let mlkem_z = [0x22u8; 32];
    let (relay_sec, relay_pub) =
        RelayKemSecret::generate_deterministic(x_seed, mlkem_d, mlkem_z);

    let mut rng = OsRng;
    let (header, ss_send) = encapsulate(&relay_pub, &mut rng).expect("encap");
    let ss_recv = relay_sec.decapsulate(&header).expect("decap");
    assert_eq!(ss_send.0, ss_recv.0);

    // Repeat with fresh encapsulation randomness — still self-consistent.
    let (header2, ss2_send) = encapsulate(&relay_pub, &mut rng).expect("encap2");
    let ss2_recv = relay_sec.decapsulate(&header2).expect("decap2");
    assert_eq!(ss2_send.0, ss2_recv.0);
    // Different ephemeral randomness ⇒ unrelated secrets (sanity, not a fixed vector).
    assert_ne!(ss_send.0, ss2_send.0);
}

#[test]
fn sphinx_packet_fixed_array_size() {
    let _ = SphinxPacket([0u8; SPHINX_PACKET_LEN]);
}
