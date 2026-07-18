//! Wave S2 — threat-model gap properties for `aegis-crypto`.
//!
//! Closes or quantifies Open/Partial rows from
//! `docs/AEGIS_implementation_threat_model.md` §1 (crypto) and crypto-adjacent
//! link / fragment / replay / client-send trust boundaries.
//!
//! See `docs/ops/CRYPTO_THREAT_GAP_LEDGER.md` for the gap → test/assumption map.
//! Deliberately separate from `vectors.rs` (Phase-2 gate rewrite coordination).

use aegis_crypto::cell::CELL_LEN;
use aegis_crypto::fragment::{
    fragment, reassemble, FRAGMENT_PAYLOAD_LEN, SPHINX_FRAGMENT_COUNT,
};
use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::link::{
    link_handshake_confirm_mac, link_handshake_finish_mac, link_handshake_init_write,
    link_handshake_initiator_finish, link_handshake_resp_write, link_handshake_responder_finish,
    parse_link_handshake_init, parse_link_handshake_resp, LinkHandshakeBinding,
    LinkHandshakeTranscript, LinkKey, LINK_FRAME_LEN,
};
use aegis_crypto::replay::ReplayCache;
use aegis_crypto::sphinx::{
    build, process, PathHop, Processed, DELTA_LEN, GAMMA_LEN, MAX_HOPS, SPHINX_PACKET_LEN,
};
use aegis_crypto::CryptoError;
use proptest::prelude::*;
use rand_core::{OsRng, RngCore};

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

fn make_path_with_ids(ids: &[[u8; 32]]) -> (Vec<PathHop>, Vec<RelayKemSecret>) {
    let mut rng = OsRng;
    let mut hops = Vec::new();
    let mut secrets = Vec::new();
    for id in ids {
        let (sec, pk) = RelayKemSecret::generate(&mut rng);
        hops.push(PathHop {
            id: *id,
            pk,
        });
        secrets.push(sec);
    }
    (hops, secrets)
}

fn unique_tag(i: u64) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[..8].copy_from_slice(&i.to_le_bytes());
    t
}

// ── TM-CRYPTO-01: opaque hop id trusted by crypto layer ─────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Crypto layer treats hop ids as opaque caller-supplied bytes (no PKI).
    /// Property: peel reveals exactly the next-hop id the builder embedded.
    #[test]
    fn opaque_hop_ids_roundtrip_on_peel(
        id0 in any::<[u8; 32]>(),
        id1 in any::<[u8; 32]>(),
        id2 in any::<[u8; 32]>(),
    ) {
        prop_assume!(id0 != id1 && id1 != id2);
        let (path, secrets) = make_path_with_ids(&[id0, id1, id2]);
        let mut rng = OsRng;
        let packet = build(&path, b"gap-01", &mut rng).expect("build");
        let mut replay = ReplayCache::with_capacity(64);
        match process(&packet, &secrets[0], &mut replay).expect("peel hop0") {
            Processed::Forward { next_hop, .. } => {
                prop_assert_eq!(next_hop, id1, "crypto must echo caller-supplied next hop");
            }
            other => prop_assert!(false, "expected Forward, got {:?}", other),
        }
    }
}

// ── TM-CRYPTO-02: link identity binding + AEAD anonymity ────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        ..ProptestConfig::default()
    })]

    /// Stolen peer-A binding cannot authenticate as peer B (identity MAC binding).
    #[test]
    fn link_binding_rejects_wrong_peer_id(
        peer_a in any::<[u8; 32]>(),
        peer_b in any::<[u8; 32]>(),
        psk in any::<[u8; 32]>(),
    ) {
        prop_assume!(peer_a != peer_b);
        let mut rng = OsRng;
        let bind_a = LinkHandshakeBinding::peer_id(peer_a);
        let bind_b = LinkHandshakeBinding::peer_id(peer_b);
        let (init_sk, init_msg) = link_handshake_init_write(&mut rng);
        let init = parse_link_handshake_init(&init_msg).unwrap();
        let (resp_sk, resp_msg) = link_handshake_resp_write(&mut rng);
        let resp = parse_link_handshake_resp(&resp_msg).unwrap();
        let transcript = LinkHandshakeTranscript::from_messages(&init, &resp);
        let confirm = link_handshake_confirm_mac(&psk, &transcript, Some(&bind_a));
        let finish = link_handshake_finish_mac(&psk, &transcript, Some(&bind_a));
        assert!(link_handshake_initiator_finish(
            &psk,
            init_sk,
            &init,
            &resp_msg,
            &finish,
            Some(&bind_a),
        )
        .is_ok());
        let err = link_handshake_responder_finish(
            &psk,
            resp_sk,
            &init,
            &resp,
            &confirm,
            Some(&bind_b),
        );
        prop_assert!(
            matches!(err, Err(CryptoError::IntegrityFailure)),
            "wrong peer id must fail closed"
        );
    }

    /// Mismatched KEM commitment binding fails closed (crypto-adjacent roster bind).
    #[test]
    fn link_binding_rejects_wrong_kem_commitment(
        peer in any::<[u8; 32]>(),
        c1 in any::<[u8; 32]>(),
        c2 in any::<[u8; 32]>(),
        psk in any::<[u8; 32]>(),
    ) {
        prop_assume!(c1 != c2);
        let mut rng = OsRng;
        let bind_a = LinkHandshakeBinding::peer_id(peer).with_kem_commitment(c1);
        let bind_b = LinkHandshakeBinding::peer_id(peer).with_kem_commitment(c2);
        let (init_sk, init_msg) = link_handshake_init_write(&mut rng);
        let init = parse_link_handshake_init(&init_msg).unwrap();
        let (resp_sk, resp_msg) = link_handshake_resp_write(&mut rng);
        let resp = parse_link_handshake_resp(&resp_msg).unwrap();
        let transcript = LinkHandshakeTranscript::from_messages(&init, &resp);
        let confirm = link_handshake_confirm_mac(&psk, &transcript, Some(&bind_a));
        let finish = link_handshake_finish_mac(&psk, &transcript, Some(&bind_a));
        let _ = link_handshake_initiator_finish(
            &psk,
            init_sk,
            &init,
            &resp_msg,
            &finish,
            Some(&bind_a),
        )
        .unwrap();
        let err = link_handshake_responder_finish(
            &psk,
            resp_sk,
            &init,
            &resp,
            &confirm,
            Some(&bind_b),
        );
        prop_assert!(matches!(err, Err(CryptoError::IntegrityFailure)));
    }
}

#[test]
fn link_aead_frame_has_fixed_width_without_peer_id_field() {
    // Residual accepted: AEAD frames carry no roster RelayId field — anonymity by design.
    // Quantify: frame length is nonce||cell||tag only; seal/open works for any cell.
    let key = LinkKey::new([0xAEu8; 32]);
    let cell = aegis_crypto::cell::Cell::zeroed();
    let mut rng = OsRng;
    let frame = key.seal(&cell, &mut rng).expect("seal");
    assert_eq!(frame.len(), LINK_FRAME_LEN);
    assert_eq!(
        LINK_FRAME_LEN,
        12 + CELL_LEN + 16,
        "frame layout is nonce+cell+tag only (no peer id slot)"
    );
    let opened = key.open(&frame).expect("open");
    assert_eq!(opened.as_bytes(), cell.as_bytes());
}

// ── TM-CRYPTO-03: MAC verify functional fail-closed (timing residual → S6) ──

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 48,
        ..ProptestConfig::default()
    })]

    /// Tampered gamma always fails `process` with IntegrityFailure (fail-closed).
    /// Timing of the post-`ct_eq` branch is an accepted residual (dudect / S6).
    #[test]
    fn tampered_gamma_always_integrity_failure(
        flip_byte in 0usize..GAMMA_LEN,
        flip_bit in 0u8..8,
    ) {
        let (path, secrets) = make_path(3);
        let mut rng = OsRng;
        let mut packet = build(&path, b"gap-03", &mut rng).expect("build");
        let gamma_off = SPHINX_PACKET_LEN - DELTA_LEN - GAMMA_LEN;
        packet.0[gamma_off + flip_byte] ^= 1u8 << flip_bit;

        let mut replay = ReplayCache::with_capacity(32);
        let err = process(&packet, &secrets[0], &mut replay).unwrap_err();
        prop_assert!(
            matches!(err, CryptoError::IntegrityFailure),
            "tampered gamma must fail closed"
        );
        // Honest packet still peels (MAC path is selective, not always-fail).
        let clean = build(&path, b"gap-03-ok", &mut rng).expect("build clean");
        prop_assert!(process(&clean, &secrets[0], &mut replay).is_ok());
    }
}

// ── TM-CRYPTO-04: fixed size / fragment flood surface (rate limit out-of-crate)

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 32,
        ..ProptestConfig::default()
    })]

    /// Packet size and fragment count are constant — DoS surface is fixed-width, not variable.
    /// Explicit rate limiting is accepted as out-of-crate (relay ingress).
    #[test]
    fn fixed_packet_and_fragment_surface(
        path_len in 2usize..=MAX_HOPS,
        payload_len in 0usize..=DELTA_LEN,
        packet_id in any::<[u8; 8]>(),
    ) {
        let (path, _) = make_path(path_len);
        let mut rng = OsRng;
        let mut payload = vec![0u8; payload_len];
        rng.fill_bytes(&mut payload);
        let packet = build(&path, &payload, &mut rng).expect("build");
        prop_assert_eq!(packet.as_bytes().len(), SPHINX_PACKET_LEN);
        prop_assert_eq!(SPHINX_PACKET_LEN, 8512, "canonical Sphinx size (not stale 8504)");

        let cells = fragment(&packet, packet_id);
        prop_assert_eq!(cells.len(), SPHINX_FRAGMENT_COUNT);
        prop_assert_eq!(SPHINX_FRAGMENT_COUNT, 18);
        for cell in &cells {
            prop_assert_eq!(cell.as_bytes().len(), CELL_LEN);
        }
        let rebuilt = reassemble(&cells).expect("reassemble");
        prop_assert_eq!(rebuilt.as_bytes(), packet.as_bytes());
        let _ = FRAGMENT_PAYLOAD_LEN;
    }
}

// ── TM-CRYPTO-05: replay window properties + capacity residual ──────────────

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Fresh tags accepted once; exact duplicates rejected while still in window.
    #[test]
    fn replay_rejects_duplicates_in_window(n in 1usize..48) {
        let mut cache = ReplayCache::with_capacity(64);
        for i in 0..n {
            let t = unique_tag(i as u64);
            prop_assert!(cache.check_and_insert(t), "first insert {}", i);
            prop_assert!(!cache.check_and_insert(t), "duplicate {}", i);
        }
        prop_assert_eq!(cache.len(), n);
    }

    /// Under flood past capacity, len never exceeds capacity (DoS backstop).
    #[test]
    fn replay_len_bounded_under_flood(extra in 1usize..32) {
        let cap = 16usize;
        let mut cache = ReplayCache::with_capacity(cap);
        for i in 0..(cap + extra) {
            prop_assert!(cache.check_and_insert(unique_tag(i as u64)));
            prop_assert!(cache.len() <= cap);
        }
        prop_assert_eq!(cache.len(), cap);
    }
}

#[test]
fn sphinx_packet_len_matches_layout_constants() {
    use aegis_crypto::kem::KEM_HEADER_LEN;
    use aegis_crypto::sphinx::{ALPHA_LEN, BETA_LEN, ROUTING_SLOT_LEN};
    assert_eq!(ALPHA_LEN, KEM_HEADER_LEN);
    assert_eq!(ROUTING_SLOT_LEN, 32 + KEM_HEADER_LEN + GAMMA_LEN);
    assert_eq!(BETA_LEN, MAX_HOPS * ROUTING_SLOT_LEN);
    assert_eq!(
        SPHINX_PACKET_LEN,
        ALPHA_LEN + BETA_LEN + GAMMA_LEN + DELTA_LEN
    );
    assert_eq!(SPHINX_PACKET_LEN, 8512);
}

// ── Client-send crypto trust boundary (documented; binding tested in client) ─

#[test]
fn client_send_path_crypto_boundary_note() {
    // TM-CLIENT-01/02: opaque PathHop::id + KEM binding enforced in aegis-client
    // (`build_packet_require_bindings`, tests/kem_binding.rs). Crypto crate trusts
    // caller-supplied ids (TM-CRYPTO-01). Raw unpaced send is soft-closed via
    // deprecated API + PacedSession default — not re-tested here.
    assert!(
        MAX_HOPS >= 2,
        "client paths of length >= 2 are the crypto build minimum"
    );
}
