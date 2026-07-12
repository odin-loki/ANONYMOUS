//! Coarse statistical smoke test for MAC-verification timing.
//!
//! This is **not** a rigorous side-channel proof — real constant-time verification
//! needs `dudect` / `ctgrind` in a controlled, isolated environment (future work).

use aegis_crypto::kem::RelayKemSecret;
use aegis_crypto::sphinx::{build, verify_mac, PathHop, SphinxPacket, SPHINX_PACKET_LEN};
use rand_core::OsRng;
use std::time::Instant;

fn sample_packet() -> (SphinxPacket, RelayKemSecret) {
    let mut rng = OsRng;
    let (sec, pk) = RelayKemSecret::generate(&mut rng);
    let mut id = [0u8; 32];
    id[0] = 1;
    let path = vec![
        PathHop { id, pk: pk.clone() },
        PathHop {
            id: [2u8; 32],
            pk: {
                let (_, p) = RelayKemSecret::generate(&mut rng);
                p
            },
        },
    ];
    let packet = build(&path, b"timing-smoke", &mut rng).unwrap();
    (packet, sec)
}

fn median_ns(samples: &mut [u64]) -> u64 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[test]
fn mac_verify_timing_smoke_no_gross_skew() {
    const TRIALS: usize = 2_000;
    let (good, relay_sec) = sample_packet();
    let secret = relay_sec
        .decapsulate(&aegis_crypto::kem::KemHeader::read_from(
            &good.as_bytes()[..aegis_crypto::kem::KEM_HEADER_LEN],
        )
        .unwrap())
        .unwrap();

    let mut bad = good.clone();
    bad.0[SPHINX_PACKET_LEN - 1] ^= 0xFF;

    let mut good_times = Vec::with_capacity(TRIALS);
    let mut bad_times = Vec::with_capacity(TRIALS);

    for _ in 0..TRIALS {
        let t0 = Instant::now();
        let _ = verify_mac(&secret, &good);
        good_times.push(t0.elapsed().as_nanos() as u64);

        let t1 = Instant::now();
        let _ = verify_mac(&secret, &bad);
        bad_times.push(t1.elapsed().as_nanos() as u64);
    }

    let good_med = median_ns(&mut good_times);
    let bad_med = median_ns(&mut bad_times);

    // Allow up to 3× median ratio — coarse guard against obvious early-exit skew.
    // Windows timer resolution is noisy; this catches gross divergence only.
    let ratio = if good_med > bad_med {
        good_med as f64 / bad_med.max(1) as f64
    } else {
        bad_med as f64 / good_med.max(1) as f64
    };
    assert!(
        ratio < 3.0,
        "MAC verify median timing ratio too large: good={good_med}ns bad={bad_med}ns ratio={ratio:.2}"
    );
}
