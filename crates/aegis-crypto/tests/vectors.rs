//! Phase-2 acceptance gate: cryptographic property/KAT tests.
//! These MUST pass before aegis-crypto is considered done (spec §10, Phase 2 gate).

use aegis_crypto::kem::{encapsulate, RelayKemSecret};
use aegis_crypto::replay::ReplayCache;
use aegis_crypto::CryptoError;
use rand_core::OsRng;
use aegis_crypto::sphinx::{
    build, process, tamper_beta_byte, Processed, PathHop, SphinxPacket, BETA_LEN, DELTA_LEN,
    ROUTING_SLOT_LEN, SPHINX_PACKET_LEN, MAX_HOPS,
};

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

#[test]
fn path_length_boundaries_rejected() {
    let mut rng = OsRng;
    let (path2, _) = make_path(2);
    assert!(build(&path2, b"ok", &mut rng).is_ok());

    let (path6, _) = make_path(MAX_HOPS);
    assert!(build(&path6, b"ok", &mut rng).is_ok());

    let (path1, _) = make_path(1);
    assert!(matches!(
        build(&path1, b"x", &mut rng).unwrap_err(),
        CryptoError::Malformed("path length")
    ));

    let mut hops = Vec::new();
    for i in 0..MAX_HOPS + 1 {
        let (sec, pk) = RelayKemSecret::generate(&mut rng);
        let mut id = [0u8; 32];
        id[0] = i as u8;
        hops.push(PathHop { id, pk });
        drop(sec);
    }
    assert!(matches!(
        build(&hops, b"x", &mut rng).unwrap_err(),
        CryptoError::Malformed("path length")
    ));
}

#[test]
fn empty_payload_builds_and_forwards() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(3);
    let packet = build(&path, b"", &mut rng).expect("empty payload build");
    assert_eq!(packet.as_bytes().len(), SPHINX_PACKET_LEN);

    let mut replay = ReplayCache::new();
    let out = process(&packet, &secrets[0], &mut replay).expect("first hop");
    match out {
        Processed::Forward { next_hop, packet: p2 } => {
            assert_eq!(next_hop, path[1].id);
            assert_eq!(p2.as_bytes().len(), SPHINX_PACKET_LEN);
            let mut replay2 = ReplayCache::new();
            let _ = process(&p2, &secrets[1], &mut replay2).expect("second hop");
        }
        _ => panic!("expected forward"),
    }
}

#[test]
fn max_hops_multi_forward_preserves_packet_length() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(MAX_HOPS);
    let packet = build(&path, &[0xFE; DELTA_LEN], &mut rng).expect("max hops build");
    assert_eq!(packet.as_bytes().len(), SPHINX_PACKET_LEN);

    let mut current = packet;
    for hop in 0..MAX_HOPS - 1 {
        let mut replay = ReplayCache::new();
        let out = process(&current, &secrets[hop], &mut replay).expect("forward hop");
        match out {
            Processed::Forward { next_hop, packet: next } => {
                assert_eq!(next_hop, path[hop + 1].id);
                assert_eq!(next.as_bytes().len(), SPHINX_PACKET_LEN);
                current = next;
            }
            _ => panic!("expected forward at hop {hop}"),
        }
    }
}

/// Property gate: peel at hop *i* always exposes `path[i+1].id` before any later hop.
/// Not a formal Sphinx proof — guards ordering regressions in routing-slot layout.
#[test]
fn hop_peel_ordering_exposes_next_hop_ids() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(MAX_HOPS);
    let packet = build(&path, b"ordering-kat", &mut rng).expect("build");

    let mut current = packet;
    for hop in 0..MAX_HOPS - 1 {
        let mut replay = ReplayCache::new();
        let out = process(&current, &secrets[hop], &mut replay).expect("peel");
        match out {
            Processed::Forward { next_hop, packet: next } => {
                assert_eq!(
                    next_hop, path[hop + 1].id,
                    "hop {hop} must reveal next id in path order"
                );
                current = next;
            }
            other => panic!("expected forward at hop {hop}, got {other:?}"),
        }
    }
}

/// Max-path build yields exactly `MAX_HOPS - 1` forward peels (terminal hop still Forward to exit id).
#[test]
fn max_hops_forward_count_is_layers_minus_one() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(MAX_HOPS);
    let packet = build(&path, b"forward-count", &mut rng).expect("build");

    let mut current = packet;
    for hop in 0..MAX_HOPS - 1 {
        let mut replay = ReplayCache::new();
        let out = process(&current, &secrets[hop], &mut replay).expect("process");
        match out {
            Processed::Forward { next_hop, packet: next } => {
                assert_eq!(next_hop, path[hop + 1].id);
                current = next;
            }
            other => panic!("expected forward at hop {hop}, got {other:?}"),
        }
    }
    // One more peel at the exit hop still returns Forward (payload delivered out-of-band).
    let mut replay = ReplayCache::new();
    let terminal = process(&current, &secrets[MAX_HOPS - 1], &mut replay).expect("exit peel");
    assert!(
        matches!(terminal, Processed::Forward { .. }),
        "exit hop peel remains Forward for delivery sink"
    );
}

#[test]
fn peel_preserves_beta_length_and_tail_slot() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(4);
    let packet = build(&path, b"peel-pad", &mut rng).expect("build");
    let beta_before = packet.as_bytes()[aegis_crypto::sphinx::ALPHA_LEN
        ..aegis_crypto::sphinx::ALPHA_LEN + BETA_LEN]
        .to_vec();

    let mut replay = ReplayCache::new();
    let peeled = match process(&packet, &secrets[0], &mut replay).expect("peel") {
        Processed::Forward { packet: peeled, .. } => peeled,
        other => panic!("expected forward, got {other:?}"),
    };
    let beta_after = &peeled.as_bytes()[aegis_crypto::sphinx::ALPHA_LEN
        ..aegis_crypto::sphinx::ALPHA_LEN + BETA_LEN];

    assert_eq!(beta_after.len(), BETA_LEN);
    assert_ne!(beta_after, beta_before.as_slice());
    // Tail routing slot is peel-pad bytes (deterministic, non-zero).
    assert_ne!(
        beta_after[BETA_LEN - ROUTING_SLOT_LEN..BETA_LEN],
        [0u8; ROUTING_SLOT_LEN]
    );
}

#[test]
fn payload_length_boundaries() {
    let mut rng = OsRng;
    let (path, _) = make_path(3);
    assert!(build(&path, b"", &mut rng).is_ok());
    assert!(build(&path, &[0u8; DELTA_LEN], &mut rng).is_ok());
    assert!(matches!(
        build(&path, &[0u8; DELTA_LEN + 1], &mut rng).unwrap_err(),
        CryptoError::Malformed("payload too long")
    ));
}
