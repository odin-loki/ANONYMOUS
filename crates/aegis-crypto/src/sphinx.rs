//! Sphinx packet processing. §2.2, §4.1.
//!
//! # Phase-2 packet layout (distinct from the 512-byte [`crate::cell::Cell`])
//!
//! The consolidated spec's "512 B cell" figure (§4.1) is illustrative for shaped
//! emission accounting; hybrid ML-KEM-768 headers alone exceed that budget. This
//! module defines a **separate**, larger, fixed-width [`SphinxPacket`] sized for
//! `MAX_HOPS = 6` paths (covering acceptance tests for path lengths 2..=6).
//!
//! ```text
//! ┌──────────── alpha (1120 B) ────────────┬──────── beta (7104 B) ────────┬─ gamma (32 B) ─┬─ delta (256 B) ─┐
//! │ X25519 ephem (32) │ ML-KEM-768 ct (1088) │ onion routing layers (6 slots) │ hop-0 MAC      │ payload onion │
//! └────────────────────────────────────────┴───────────────────────────────┴────────────────┴───────────────┘
//! Total SPHINX_PACKET_LEN = 8512 bytes (constant for all path lengths ≤ MAX_HOPS).
//! ```
//!
//! ## Per-field cryptography
//!
//! | Field  | Primitive | Notes |
//! |--------|-----------|-------|
//! | alpha  | Hybrid KEM header | Current hop only; replaced on peel from `beta`. |
//! | beta   | SHA3-256 stream XOR per routing slot (1184 B each); shift-left peel with deterministic tail pad derived from hop secret | Six fixed slots; only `path_len-1` used. |
//! | gamma  | Keyed SHA3-256 | `SHA3-256("aegis-gamma-mac-v1" ‖ secret ‖ beta)`; next hop's MAC pre-embedded in peeled slot. |
//! | delta  | SHA3-256 stream XOR onion | Layered with every hop secret at build; one XOR peel per hop. ChaCha20-Poly1305 was deferred — wide-block LIONESS omitted for correctness risk (see `docs/AEGIS_phase2_implementation_notes.md`). |
//!
//! ## Processing order (unchanged from scaffold)
//!
//! Decap → verify gamma → replay tag → peel beta/alpha/gamma/delta.

use rand_core::{CryptoRngCore, RngCore};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

use crate::cell::Cell;
use crate::kem::{
    encapsulate, KemHeader, RelayKemPublic, RelayKemSecret, SharedSecret, KEM_HEADER_LEN,
};
use crate::replay::{ReplayCache, ReplayTag};
use crate::{CryptoError, Result};

/// Maximum path length supported by the fixed routing onion.
pub const MAX_HOPS: usize = 6;

/// Routing slot inside `beta`: next hop id, next hop's KEM header, next hop's gamma MAC.
pub const ROUTING_SLOT_LEN: usize = 32 + KEM_HEADER_LEN + 32;

pub const ALPHA_LEN: usize = KEM_HEADER_LEN;
pub const BETA_LEN: usize = MAX_HOPS * ROUTING_SLOT_LEN;
pub const GAMMA_LEN: usize = 32;
pub const DELTA_LEN: usize = 256;
pub const SPHINX_PACKET_LEN: usize = ALPHA_LEN + BETA_LEN + GAMMA_LEN + DELTA_LEN;

const OFF_ALPHA: usize = 0;
const OFF_BETA: usize = ALPHA_LEN;
const OFF_GAMMA: usize = OFF_BETA + BETA_LEN;
const OFF_DELTA: usize = OFF_GAMMA + GAMMA_LEN;

const STREAM_BETA: &[u8] = b"aegis-beta-stream-v1";
const STREAM_DELTA: &[u8] = b"aegis-delta-stream-v1";
const MAC_DOMAIN: &[u8] = b"aegis-gamma-mac-v1";
const REPLAY_DOMAIN: &[u8] = b"aegis-replay-tag-v1";

/// A fixed-size Sphinx packet (not the 512-byte link-layer [`Cell`]).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SphinxPacket(pub [u8; SPHINX_PACKET_LEN]);

impl SphinxPacket {
    pub fn as_bytes(&self) -> &[u8; SPHINX_PACKET_LEN] {
        &self.0
    }

    pub fn from_bytes(bytes: [u8; SPHINX_PACKET_LEN]) -> Self {
        Self(bytes)
    }
}

/// One hop in a path used when building a packet (client-side).
pub struct PathHop {
    pub id: [u8; 32],
    pub pk: RelayKemPublic,
}

/// The result of processing one packet at a mix.
#[derive(Debug)]
pub enum Processed {
    /// Forward the peeled packet to `next_hop`.
    Forward {
        next_hop: [u8; 32],
        packet: SphinxPacket,
    },
    /// A loop cover cell that returned to this node (active-attack detector).
    LoopReturned,
    /// A drop/cover cell — discard silently.
    Drop,
}

/// Build a Sphinx packet along `path` (2..=MAX_HOPS hops) with `payload` in `delta`.
pub fn build<R: RngCore + CryptoRngCore>(
    path: &[PathHop],
    payload: &[u8],
    rng: &mut R,
) -> Result<SphinxPacket> {
    if path.len() < 2 || path.len() > MAX_HOPS {
        return Err(CryptoError::Malformed("path length"));
    }
    if payload.len() > DELTA_LEN {
        return Err(CryptoError::Malformed("payload too long"));
    }

    let n = path.len();
    let layers = n - 1;

    let mut headers = Vec::with_capacity(n);
    let mut secrets = Vec::with_capacity(n);
    for hop in path {
        let (hdr, sec) = encapsulate(&hop.pk, rng)?;
        headers.push(hdr);
        secrets.push(sec);
    }

    let mut beta = vec![0u8; BETA_LEN];
    rng.fill_bytes(&mut beta);

    // Pass 1: routing slots (next_gamma placeholder = 0), per-slot stream encryption.
    for i in 0..layers {
        let off = i * ROUTING_SLOT_LEN;
        beta[off..off + 32].copy_from_slice(&path[i + 1].id);
        headers[i + 1].write_to(&mut beta[off + 32..off + 32 + KEM_HEADER_LEN]);
    }
    encrypt_slots(&mut beta, layers, &secrets[..layers]);
    decrypt_slots(&mut beta, layers, &secrets[..layers]);

    // Embed next-hop MACs inside-out: outer slot MACs depend on inner slots already
    // carrying their gamma fields (shifts during peel expose inner-slot bytes).
    let mut next_gammas = vec![[0u8; GAMMA_LEN]; layers];
    for i in (0..layers).rev() {
        for j in (i + 1)..layers {
            let off = j * ROUTING_SLOT_LEN + 32 + KEM_HEADER_LEN;
            beta[off..off + GAMMA_LEN].copy_from_slice(&next_gammas[j]);
        }
        encrypt_slots(&mut beta, layers, &secrets[..layers]);
        next_gammas[i] = mac_after_peels(&beta, &secrets, i + 1);
        decrypt_slots(&mut beta, layers, &secrets[..layers]);
    }

    for i in 0..layers {
        let off = i * ROUTING_SLOT_LEN + 32 + KEM_HEADER_LEN;
        beta[off..off + GAMMA_LEN].copy_from_slice(&next_gammas[i]);
    }
    encrypt_slots(&mut beta, layers, &secrets[..layers]);

    let gamma = compute_mac(&secrets[0], &beta);

    let mut delta = [0u8; DELTA_LEN];
    delta[..payload.len()].copy_from_slice(payload);
    rng.fill_bytes(&mut delta[payload.len()..]);
    for sec in &secrets {
        stream_xor_range(&mut delta, 0, DELTA_LEN, sec, STREAM_DELTA);
    }

    let mut packet = [0u8; SPHINX_PACKET_LEN];
    headers[0].write_to(&mut packet[OFF_ALPHA..OFF_ALPHA + ALPHA_LEN]);
    packet[OFF_BETA..OFF_BETA + BETA_LEN].copy_from_slice(&beta);
    packet[OFF_GAMMA..OFF_GAMMA + GAMMA_LEN].copy_from_slice(&gamma);
    packet[OFF_DELTA..OFF_DELTA + DELTA_LEN].copy_from_slice(&delta);

    Ok(SphinxPacket(packet))
}

/// Derive the 32-byte replay tag from the per-hop shared secret.
pub fn replay_tag(secret: &SharedSecret) -> ReplayTag {
    let mut h = Sha3_256::new();
    h.update(REPLAY_DOMAIN);
    h.update(&secret.0);
    h.finalize().into()
}

/// Verify the integrity MAC (gamma) over the routing header (beta).
pub fn verify_mac(secret: &SharedSecret, packet: &SphinxPacket) -> bool {
    let expected = compute_mac(secret, beta_slice(packet));
    let actual = &packet.0[OFF_GAMMA..OFF_GAMMA + GAMMA_LEN];
    expected.ct_eq(actual).into()
}

/// Process one inbound packet at a mix. Integrity and replay are checked before peeling.
pub fn process(
    packet: &SphinxPacket,
    relay_secret: &RelayKemSecret,
    replay: &mut ReplayCache,
) -> Result<Processed> {
    let header = extract_kem_header(packet)?;
    let secret = relay_secret.decapsulate(&header)?;

    if !verify_mac(&secret, packet) {
        return Err(CryptoError::IntegrityFailure);
    }

    if !replay.check_and_insert(replay_tag(&secret)) {
        return Err(CryptoError::Replay);
    }

    peel(packet, &secret)
}

fn extract_kem_header(packet: &SphinxPacket) -> Result<KemHeader> {
    KemHeader::read_from(&packet.0[OFF_ALPHA..OFF_ALPHA + ALPHA_LEN])
}

fn peel(packet: &SphinxPacket, secret: &SharedSecret) -> Result<Processed> {
    let mut out = packet.0;

    stream_xor_range(&mut out, OFF_BETA, OFF_BETA + ROUTING_SLOT_LEN, secret, STREAM_BETA);

    let next_hop: [u8; 32] = out[OFF_BETA..OFF_BETA + 32].try_into().expect("32");
    let next_header = KemHeader::read_from(
        &out[OFF_BETA + 32..OFF_BETA + 32 + KEM_HEADER_LEN],
    )?;
    let next_gamma: [u8; GAMMA_LEN] = out[OFF_BETA + 32 + KEM_HEADER_LEN
        ..OFF_BETA + 32 + KEM_HEADER_LEN + GAMMA_LEN]
        .try_into()
        .expect("32");

    // Shift beta left by one routing slot; pad tail deterministically (length unchanged).
    let tail_start = OFF_BETA + ROUTING_SLOT_LEN;
    out.copy_within(tail_start..OFF_BETA + BETA_LEN, OFF_BETA);
    let pad = peel_pad(secret, ROUTING_SLOT_LEN);
    out[OFF_BETA + BETA_LEN - ROUTING_SLOT_LEN..OFF_BETA + BETA_LEN].copy_from_slice(&pad);

    next_header.write_to(&mut out[OFF_ALPHA..OFF_ALPHA + ALPHA_LEN]);
    out[OFF_GAMMA..OFF_GAMMA + GAMMA_LEN].copy_from_slice(&next_gamma);

    stream_xor_range(&mut out, OFF_DELTA, OFF_DELTA + DELTA_LEN, secret, STREAM_DELTA);

    Ok(Processed::Forward {
        next_hop,
        packet: SphinxPacket(out),
    })
}

fn encrypt_slots(beta: &mut [u8], layers: usize, secrets: &[SharedSecret]) {
    for i in 0..layers {
        let off = i * ROUTING_SLOT_LEN;
        stream_xor_range(beta, off, off + ROUTING_SLOT_LEN, &secrets[i], STREAM_BETA);
    }
}

fn decrypt_slots(beta: &mut [u8], layers: usize, secrets: &[SharedSecret]) {
    for i in 0..layers {
        let off = i * ROUTING_SLOT_LEN;
        stream_xor_range(beta, off, off + ROUTING_SLOT_LEN, &secrets[i], STREAM_BETA);
    }
}

fn peel_pad(secret: &SharedSecret, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut counter: u64 = 0;
    let mut pos = 0;
    while pos < len {
        let mut h = Sha3_256::new();
        h.update(b"aegis-beta-peel-pad-v1");
        h.update(&secret.0);
        h.update(&counter.to_le_bytes());
        let block = h.finalize();
        for byte in block {
            if pos >= len {
                break;
            }
            out[pos] = byte;
            pos += 1;
        }
        counter += 1;
    }
    out
}

fn mac_after_peels(beta: &[u8], secrets: &[SharedSecret], peels: usize) -> [u8; GAMMA_LEN] {
    let mut work = beta.to_vec();
    for h in 0..peels {
        stream_xor_range(&mut work, 0, ROUTING_SLOT_LEN, &secrets[h], STREAM_BETA);
        work.copy_within(ROUTING_SLOT_LEN..BETA_LEN, 0);
        let pad = peel_pad(&secrets[h], ROUTING_SLOT_LEN);
        work[BETA_LEN - ROUTING_SLOT_LEN..BETA_LEN].copy_from_slice(&pad);
    }
    compute_mac(&secrets[peels], &work)
}

fn beta_slice(packet: &SphinxPacket) -> &[u8] {
    &packet.0[OFF_BETA..OFF_BETA + BETA_LEN]
}

fn compute_mac(secret: &SharedSecret, beta: &[u8]) -> [u8; GAMMA_LEN] {
    let mut h = Sha3_256::new();
    h.update(MAC_DOMAIN);
    h.update(&secret.0);
    h.update(beta);
    h.finalize().into()
}

fn stream_xor_range(
    buf: &mut [u8],
    start: usize,
    end: usize,
    secret: &SharedSecret,
    domain: &[u8],
) {
    let mut counter: u64 = 0;
    let mut pos = start;
    while pos < end {
        let mut h = Sha3_256::new();
        h.update(domain);
        h.update(&secret.0);
        h.update(&counter.to_le_bytes());
        let block = h.finalize();
        for byte in block {
            if pos >= end {
                break;
            }
            buf[pos] ^= byte;
            pos += 1;
        }
        counter += 1;
    }
}

/// Test helper: flip one byte in `beta`.
#[doc(hidden)]
pub fn tamper_beta_byte(packet: &mut SphinxPacket, offset: usize) {
    packet.0[OFF_BETA + offset] ^= 0x01;
}

// Legacy `Cell`-based entry points retained for API stability during transition.
// Link-layer cells are separate; Sphinx uses [`SphinxPacket`].

/// Process a legacy [`Cell`] wrapper — returns malformed (Sphinx uses [`SphinxPacket`]).
pub fn process_cell(
    _packet: &Cell,
    _relay_secret: &RelayKemSecret,
    _replay: &mut ReplayCache,
) -> Result<Processed> {
    Err(CryptoError::Malformed("expected SphinxPacket, not Cell"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::{encapsulate, RelayKemSecret, SharedSecret};
    use crate::replay::ReplayCache;
    use rand_core::OsRng;

    fn sample_path(n: usize) -> (Vec<PathHop>, Vec<RelayKemSecret>) {
        let mut rng = OsRng;
        let mut hops = Vec::new();
        let mut secrets = Vec::new();
        for i in 0..n {
            let (sec, pk) = RelayKemSecret::generate(&mut rng);
            let mut id = [0u8; 32];
            id[0] = i as u8;
            hops.push(PathHop { id, pk });
            secrets.push(sec);
        }
        (hops, secrets)
    }

    #[test]
    fn build_and_process_forward() {
        let (path, secrets) = sample_path(3);
        let mut rng = OsRng;
        let packet = build(&path, b"hello", &mut rng).unwrap();
        let mut replay = ReplayCache::new();
        let out = process(&packet, &secrets[0], &mut replay).unwrap();
        match out {
            Processed::Forward { next_hop, packet: p2 } => {
                assert_eq!(next_hop, path[1].id);
                let mut replay2 = ReplayCache::new();
                let _ = process(&p2, &secrets[1], &mut replay2).unwrap();
            }
            _ => panic!("expected forward"),
        }
    }

    #[test]
    fn tamper_at_multiple_offsets_fails() {
        let (path, secrets) = sample_path(4);
        let mut rng = OsRng;
        let packet = build(&path, b"x", &mut rng).unwrap();
        for off in [0, 31, 32, ROUTING_SLOT_LEN, BETA_LEN - 1] {
            let mut tampered = packet.clone();
            tamper_beta_byte(&mut tampered, off);
            let mut replay = ReplayCache::new();
            let err = process(&tampered, &secrets[0], &mut replay).unwrap_err();
            assert!(matches!(err, CryptoError::IntegrityFailure));
        }
    }

    #[test]
    fn double_replay_rejected() {
        let (path, secrets) = sample_path(2);
        let mut rng = OsRng;
        let packet = build(&path, b"z", &mut rng).unwrap();
        let mut replay = ReplayCache::new();
        process(&packet, &secrets[0], &mut replay).unwrap();
        let err = process(&packet, &secrets[0], &mut replay).unwrap_err();
        assert!(matches!(err, CryptoError::Replay));
    }

    #[test]
    fn peel_pad_is_deterministic_and_full_length() {
        let mut rng = OsRng;
        let (relay_sec, relay_pub) = RelayKemSecret::generate(&mut rng);
        let (hdr, shared) = encapsulate(&relay_pub, &mut rng).unwrap();
        assert_eq!(relay_sec.decapsulate(&hdr).unwrap().0, shared.0);
        let sec = SharedSecret(shared.0);
        let pad1 = peel_pad(&sec, ROUTING_SLOT_LEN);
        let pad2 = peel_pad(&sec, ROUTING_SLOT_LEN);
        assert_eq!(pad1, pad2);
        assert_eq!(pad1.len(), ROUTING_SLOT_LEN);
        assert_ne!(pad1, vec![0u8; ROUTING_SLOT_LEN]);
    }

    #[test]
    fn consecutive_peels_preserve_packet_length() {
        let (path, secrets) = sample_path(5);
        let mut rng = OsRng;
        let packet = build(&path, b"layer", &mut rng).unwrap();
        let mut current = packet;
        for hop in 0..4 {
            let mut replay = ReplayCache::new();
            let next = match process(&current, &secrets[hop], &mut replay).unwrap() {
                Processed::Forward { packet: next, .. } => next,
                other => panic!("expected forward at hop {hop}, got {other:?}"),
            };
            assert_eq!(next.as_bytes().len(), SPHINX_PACKET_LEN);
            current = next;
        }
    }

    /// Shared KATs with `sim/aegis_sim/sphinx_oracle.py` (wave S1).
    /// Independent reimplementation cross-check — not a formal proof.
    #[test]
    fn python_oracle_shared_primitive_kats() {
        let secret = SharedSecret([0x11u8; 32]);

        let mut buf: Vec<u8> = (0u8..64).collect();
        stream_xor_range(&mut buf, 0, 64, &secret, STREAM_BETA);
        const STREAM_EXPECT: [u8; 64] = [
            0x88, 0x6a, 0x14, 0x34, 0xc5, 0x8d, 0x44, 0x33, 0x66, 0x68, 0x2c, 0xfb, 0xdd, 0x77,
            0x72, 0x66, 0xc5, 0xb9, 0xdd, 0x2f, 0x40, 0x9c, 0xc6, 0xb6, 0x7f, 0xe4, 0x34, 0x03,
            0xbc, 0xba, 0x5d, 0x8a, 0xe3, 0xda, 0x3a, 0x10, 0xe0, 0x8f, 0x5e, 0x33, 0x98, 0x2f,
            0x8e, 0xd5, 0xc5, 0x55, 0xcf, 0x60, 0x22, 0xfc, 0x7b, 0x92, 0xf4, 0xa7, 0xcc, 0x30,
            0x7a, 0xf4, 0x80, 0x92, 0xbe, 0x68, 0xdd, 0x56,
        ];
        assert_eq!(buf.as_slice(), STREAM_EXPECT.as_slice());

        let pad = peel_pad(&secret, ROUTING_SLOT_LEN);
        assert_eq!(pad.len(), ROUTING_SLOT_LEN);
        const PAD_PREFIX: [u8; 32] = [
            0x41, 0x83, 0x45, 0x55, 0xfd, 0xf9, 0x3e, 0x92, 0x29, 0x94, 0xc7, 0xd9, 0xc4, 0x40,
            0x4b, 0x02, 0x53, 0x0a, 0x44, 0xcc, 0x9e, 0xed, 0xa1, 0x82, 0x7e, 0x37, 0x85, 0x00,
            0xf4, 0x86, 0x61, 0x02,
        ];
        assert_eq!(&pad[..32], PAD_PREFIX.as_slice());

        let beta: Vec<u8> = (0..BETA_LEN).map(|i| ((i * 17) % 256) as u8).collect();
        let mac = compute_mac(&secret, &beta);
        const MAC_EXPECT: [u8; 32] = [
            0x1e, 0x77, 0x4c, 0xf2, 0x57, 0x30, 0x9c, 0x85, 0xb5, 0x58, 0xef, 0x27, 0xea, 0xc3,
            0xb4, 0x12, 0xef, 0x79, 0x2a, 0x55, 0xbc, 0xe1, 0x51, 0xe1, 0x03, 0x90, 0xe1, 0xdb,
            0x22, 0xf9, 0xf3, 0xcc,
        ];
        assert_eq!(mac, MAC_EXPECT);

        const REPLAY_EXPECT: [u8; 32] = [
            0x26, 0x1d, 0x03, 0x7e, 0xad, 0x23, 0xe8, 0xbc, 0x7a, 0x09, 0x2e, 0x7f, 0x36, 0x23,
            0xea, 0x4c, 0x78, 0x60, 0x7f, 0x6f, 0x9a, 0x44, 0x09, 0x70, 0x2a, 0x1f, 0x0e, 0xb5,
            0xa8, 0x61, 0x83, 0xac,
        ];
        assert_eq!(replay_tag(&secret), REPLAY_EXPECT);

        assert_eq!(SPHINX_PACKET_LEN, 8512);
    }
}
