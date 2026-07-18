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

/// Peel-order KAT for minimum path (2 hops): hop-0 reveals hop-1 id only.
#[test]
fn two_hop_peel_order_kat() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(2);
    let packet = build(&path, b"two-hop-kat", &mut rng).expect("build");

    let mut replay = ReplayCache::new();
    let out = process(&packet, &secrets[0], &mut replay).expect("hop0");
    match out {
        Processed::Forward { next_hop, packet: next } => {
            assert_eq!(next_hop, path[1].id);
            assert_eq!(next.as_bytes().len(), SPHINX_PACKET_LEN);
            let mut replay1 = ReplayCache::new();
            let terminal = process(&next, &secrets[1], &mut replay1).expect("hop1");
            assert!(matches!(terminal, Processed::Forward { .. }));
        }
        other => panic!("expected forward, got {other:?}"),
    }
}

/// Peel-order KAT for 3 hops: each hop reveals exactly the next id in sequence.
#[test]
fn three_hop_peel_order_kat() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(3);
    let packet = build(&path, b"three-hop-kat", &mut rng).expect("build");

    let mut current = packet;
    for hop in 0..2 {
        let mut replay = ReplayCache::new();
        match process(&current, &secrets[hop], &mut replay).expect("peel") {
            Processed::Forward { next_hop, packet: next } => {
                assert_eq!(next_hop, path[hop + 1].id, "hop {hop} next-hop mismatch");
                current = next;
            }
            other => panic!("expected forward at hop {hop}, got {other:?}"),
        }
    }
}

/// Wrong-hop secret at hop 0 must fail integrity (cannot skip peel order).
#[test]
fn wrong_hop_secret_rejected_at_entry() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(4);
    let packet = build(&path, b"wrong-hop", &mut rng).expect("build");
    let mut replay = ReplayCache::new();
    // Use hop-2 secret against hop-0 ciphertext — must not peel.
    let err = process(&packet, &secrets[2], &mut replay).unwrap_err();
    assert!(matches!(err, CryptoError::IntegrityFailure | CryptoError::Malformed(_)));
}

/// Intermediate hop cannot successfully peel with a later hop's secret.
#[test]
fn later_hop_secret_cannot_peel_intermediate_packet() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(4);
    let packet = build(&path, b"mid-hop", &mut rng).expect("build");

    let mut replay0 = ReplayCache::new();
    let mid = match process(&packet, &secrets[0], &mut replay0).expect("hop0") {
        Processed::Forward { packet: next, .. } => next,
        other => panic!("expected forward, got {other:?}"),
    };

    let mut replay_wrong = ReplayCache::new();
    let err = process(&mid, &secrets[3], &mut replay_wrong).unwrap_err();
    assert!(matches!(err, CryptoError::IntegrityFailure | CryptoError::Malformed(_)));

    // Correct next hop still works.
    let mut replay1 = ReplayCache::new();
    let ok = process(&mid, &secrets[1], &mut replay1).expect("hop1");
    assert!(matches!(ok, Processed::Forward { next_hop, .. } if next_hop == path[2].id));
}

/// Property: for every path length in 2..=MAX_HOPS, peel order reveals path[i+1].
/// Not a formal Sphinx proof — regression gate on routing-slot layout.
#[test]
fn peel_order_property_all_path_lengths() {
    let mut rng = OsRng;
    for len in 2..=MAX_HOPS {
        let (path, secrets) = make_path(len);
        let packet = build(&path, &[len as u8; 16], &mut rng).expect("build");
        let mut current = packet;
        for hop in 0..len - 1 {
            let mut replay = ReplayCache::new();
            match process(&current, &secrets[hop], &mut replay).expect("peel") {
                Processed::Forward { next_hop, packet: next } => {
                    assert_eq!(
                        next_hop, path[hop + 1].id,
                        "path_len={len} hop={hop} peel-order mismatch"
                    );
                    assert_eq!(next.as_bytes().len(), SPHINX_PACKET_LEN);
                    current = next;
                }
                other => panic!("path_len={len} hop={hop}: expected forward, got {other:?}"),
            }
        }
    }
}

/// Seeded structural KAT: deterministic relay keys + fixed payload → constant size
/// and peel-order stability across two builds with independent encapsulation RNG.
/// (Encapsulation uses OsRng; this is not a cross-implementation official vector.)
#[test]
fn seeded_relay_keys_build_size_and_peel_kat() {
    fn path_from_seeds(seeds: &[[u8; 32]]) -> (Vec<PathHop>, Vec<RelayKemSecret>) {
        let mut hops = Vec::new();
        let mut secrets = Vec::new();
        for (i, seed) in seeds.iter().enumerate() {
            let mut mlkem_d = [0u8; 32];
            let mut mlkem_z = [0u8; 32];
            mlkem_d[0] = 0xD0;
            mlkem_z[0] = 0xE0;
            mlkem_d[1] = i as u8;
            mlkem_z[1] = i as u8;
            let (sec, pk) = RelayKemSecret::generate_deterministic(*seed, mlkem_d, mlkem_z);
            let mut id = [0u8; 32];
            id[0] = (i as u8).wrapping_add(1);
            hops.push(PathHop { id, pk });
            secrets.push(sec);
        }
        (hops, secrets)
    }

    let seeds = [[0x11u8; 32], [0x22u8; 32], [0x33u8; 32]];
    let (path, secrets) = path_from_seeds(&seeds);
    let mut rng = OsRng;
    let p1 = build(&path, b"seeded-kat", &mut rng).expect("build1");
    let p2 = build(&path, b"seeded-kat", &mut rng).expect("build2");
    assert_eq!(p1.as_bytes().len(), SPHINX_PACKET_LEN);
    assert_eq!(p2.as_bytes().len(), SPHINX_PACKET_LEN);
    // Fresh encapsulation ⇒ distinct wire bytes, same peel-order semantics.
    assert_ne!(p1.as_bytes(), p2.as_bytes());

    for packet in [p1, p2] {
        let mut current = packet;
        for hop in 0..2 {
            let mut replay = ReplayCache::new();
            match process(&current, &secrets[hop], &mut replay).expect("peel") {
                Processed::Forward { next_hop, packet: next } => {
                    assert_eq!(next_hop, path[hop + 1].id);
                    current = next;
                }
                other => panic!("expected forward, got {other:?}"),
            }
        }
    }
}

/// Alpha/gamma tamper at hop 0 fails closed (edge case beyond beta-byte tamper).
#[test]
fn tamper_alpha_or_gamma_rejected() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(3);
    let packet = build(&path, b"tamper-regions", &mut rng).expect("build");

    let mut alpha_tampered = packet.clone();
    alpha_tampered.0[0] ^= 0x01;
    let mut replay_a = ReplayCache::new();
    assert!(matches!(
        process(&alpha_tampered, &secrets[0], &mut replay_a).unwrap_err(),
        CryptoError::IntegrityFailure | CryptoError::Malformed(_)
    ));

    let mut gamma_tampered = packet.clone();
    let gamma_off = aegis_crypto::sphinx::ALPHA_LEN + BETA_LEN;
    gamma_tampered.0[gamma_off] ^= 0x01;
    let mut replay_g = ReplayCache::new();
    assert!(matches!(
        process(&gamma_tampered, &secrets[0], &mut replay_g).unwrap_err(),
        CryptoError::IntegrityFailure
    ));
}

/// Adversarial tagging KAT (wave S1): bit-flip map across beta slot boundaries.
/// Not a formal tagging-resistance proof — regression gate on gamma covering beta.
#[test]
fn tagging_bit_flip_map_beta_rejects() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(4);
    let packet = build(&path, b"bit-flip-map", &mut rng).expect("build");
    let offsets = [
        0usize,
        31,
        32,
        ROUTING_SLOT_LEN - 1,
        ROUTING_SLOT_LEN,
        ROUTING_SLOT_LEN + 32,
        BETA_LEN / 2,
        BETA_LEN - 1,
    ];
    for off in offsets {
        let mut tampered = packet.clone();
        tamper_beta_byte(&mut tampered, off);
        let mut replay = ReplayCache::new();
        let err = process(&tampered, &secrets[0], &mut replay).unwrap_err();
        assert!(
            matches!(err, CryptoError::IntegrityFailure),
            "beta offset {off} must fail integrity"
        );
    }
}

/// Delta tamper is not covered by hop-0 gamma (MAC is over beta only).
/// Documents design: payload integrity is layered stream-XOR, not AEAD at hop-0.
#[test]
fn delta_bit_flip_does_not_fail_hop0_mac() {
    use aegis_crypto::sphinx::{ALPHA_LEN, GAMMA_LEN};

    let mut rng = OsRng;
    let (path, secrets) = make_path(3);
    let packet = build(&path, b"delta-gap", &mut rng).expect("build");

    let mut delta_tampered = packet.clone();
    let delta_off = ALPHA_LEN + BETA_LEN + GAMMA_LEN;
    delta_tampered.0[delta_off] ^= 0x01;

    // MAC over beta unchanged ⇒ process proceeds past integrity and Forwards.
    let mut replay = ReplayCache::new();
    let out = process(&delta_tampered, &secrets[0], &mut replay).expect("delta flip passes MAC");
    assert!(matches!(out, Processed::Forward { .. }));
}

/// Wrong-hop after first peel: hop-0 packet rejected by hop-1 secret (skip attack).
#[test]
fn skip_hop_secret_rejected() {
    let mut rng = OsRng;
    let (path, secrets) = make_path(5);
    let packet = build(&path, b"skip-hop", &mut rng).expect("build");

    // Attempt to process entry packet with hop-1 secret (skip hop-0).
    let mut replay = ReplayCache::new();
    let err = process(&packet, &secrets[1], &mut replay).unwrap_err();
    assert!(matches!(
        err,
        CryptoError::IntegrityFailure | CryptoError::Malformed(_)
    ));

    // Correct peel then wrong later hop still fails.
    let mut replay0 = ReplayCache::new();
    let mid = match process(&packet, &secrets[0], &mut replay0).expect("hop0") {
        Processed::Forward { packet: next, .. } => next,
        other => panic!("expected forward, got {other:?}"),
    };
    let mut replay_wrong = ReplayCache::new();
    let err2 = process(&mid, &secrets[3], &mut replay_wrong).unwrap_err();
    assert!(matches!(
        err2,
        CryptoError::IntegrityFailure | CryptoError::Malformed(_)
    ));
}

/// Path-length adversarial: payload-at-max and unused-slot randomness keep size fixed.
#[test]
fn path_length_adversarial_size_invariant() {
    let mut rng = OsRng;
    for len in 2..=MAX_HOPS {
        let (path, secrets) = make_path(len);
        let packet = build(&path, &[0xAA; DELTA_LEN], &mut rng).expect("build");
        assert_eq!(packet.as_bytes().len(), SPHINX_PACKET_LEN);
        let mut replay = ReplayCache::new();
        let out = process(&packet, &secrets[0], &mut replay).expect("hop0");
        match out {
            Processed::Forward { next_hop, packet: next } => {
                assert_eq!(next_hop, path[1].id);
                assert_eq!(next.as_bytes().len(), SPHINX_PACKET_LEN);
            }
            other => panic!("expected forward, got {other:?}"),
        }
    }
}

/// Public replay_tag KAT shared with Python oracle (secret = 0x11 * 32).
#[test]
fn replay_tag_shared_kat_with_python_oracle() {
    use aegis_crypto::kem::SharedSecret;
    use aegis_crypto::sphinx::replay_tag;

    let secret = SharedSecret([0x11u8; 32]);
    let tag = replay_tag(&secret);
    const EXPECT: [u8; 32] = [
        0x26, 0x1d, 0x03, 0x7e, 0xad, 0x23, 0xe8, 0xbc, 0x7a, 0x09, 0x2e, 0x7f, 0x36, 0x23,
        0xea, 0x4c, 0x78, 0x60, 0x7f, 0x6f, 0x9a, 0x44, 0x09, 0x70, 0x2a, 0x1f, 0x0e, 0xb5,
        0xa8, 0x61, 0x83, 0xac,
    ];
    assert_eq!(tag, EXPECT);
}
