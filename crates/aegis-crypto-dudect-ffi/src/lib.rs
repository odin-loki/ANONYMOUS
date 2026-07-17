//! C ABI probes for external [`dudect`](https://github.com/oreparaz/dudect) harnesses.
//!
//! Built from `tools/dudect/Makefile` (Linux). Not a workspace member — default
//! `cargo test --workspace` does not compile this crate.

use std::sync::OnceLock;

use aegis_crypto::kem::{KemHeader, RelayKemSecret, SharedSecret};
use aegis_crypto::replay::{ReplayCache, ReplayTag};
use aegis_crypto::sphinx::{
    build, verify_mac, PathHop, SphinxPacket, ALPHA_LEN, BETA_LEN, SPHINX_PACKET_LEN,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const OFF_GAMMA: usize = ALPHA_LEN + BETA_LEN;

const MAC_LAB_SEED: u64 = 0xAEC15_00AC_00FF;

struct ReplayLab {
    cache: ReplayCache,
    hit_tag: ReplayTag,
    miss_tag: ReplayTag,
}

struct MacLab {
    secret: SharedSecret,
    good: SphinxPacket,
    bad: SphinxPacket,
}

static REPLAY_LAB: OnceLock<ReplayLab> = OnceLock::new();
static MAC_LAB: OnceLock<MacLab> = OnceLock::new();

fn replay_tag_from_index(n: u64) -> ReplayTag {
    let mut t = [0u8; 32];
    t[..8].copy_from_slice(&n.to_le_bytes());
    t
}

fn init_replay_lab(capacity: usize) -> Result<(), i32> {
    if capacity == 0 {
        return Err(-1);
    }

    REPLAY_LAB.get_or_init(|| {
        let mut cache = ReplayCache::with_capacity(capacity);
        for i in 0..capacity {
            let tag = replay_tag_from_index(i as u64);
            assert!(cache.check_and_insert(tag));
        }
        ReplayLab {
            hit_tag: replay_tag_from_index(0),
            miss_tag: replay_tag_from_index(9_000),
            cache,
        }
    });
    Ok(())
}

fn init_mac_lab() {
    MAC_LAB.get_or_init(|| {
        let mut rng = ChaCha20Rng::seed_from_u64(MAC_LAB_SEED);
        let (relay_sec, pk) = RelayKemSecret::generate(&mut rng);
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
        let good = build(&path, b"dudect-mac-lab", &mut rng).expect("sphinx build");
        let secret = relay_sec
            .decapsulate(
                &KemHeader::read_from(&good.as_bytes()[..aegis_crypto::kem::KEM_HEADER_LEN])
                    .expect("kem header"),
            )
            .expect("decapsulate");
        let mut bad = good.clone();
        bad.0[OFF_GAMMA] ^= 0xFF;
        MacLab {
            secret,
            good,
            bad,
        }
    });
}

/// Initialize replay-cache lab with `capacity` tags (FIFO full). Idempotent.
#[no_mangle]
pub extern "C" fn aegis_dudect_replay_lab_init(capacity: u32) -> i32 {
    match init_replay_lab(capacity as usize) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

/// Initialize MAC-verify lab fixtures (deterministic seed). Idempotent.
#[no_mangle]
pub extern "C" fn aegis_dudect_mac_lab_init() {
    init_mac_lab();
}

/// `class_bit == 0` → miss; non-zero → hit.
#[no_mangle]
pub extern "C" fn aegis_ct_contains(class_bit: u8) -> u8 {
    let Some(lab) = REPLAY_LAB.get() else {
        return 0xFF;
    };
    let tag = if class_bit == 0 {
        &lab.miss_tag
    } else {
        &lab.hit_tag
    };
    u8::from(lab.cache.contains_ct(tag))
}

/// `class_bit == 0` → bad MAC; non-zero → valid packet.
#[no_mangle]
pub extern "C" fn aegis_ct_verify_mac(class_bit: u8) -> u8 {
    let Some(lab) = MAC_LAB.get() else {
        return 0xFF;
    };
    let packet = if class_bit == 0 {
        &lab.bad
    } else {
        &lab.good
    };
    u8::from(verify_mac(&lab.secret, packet))
}

#[no_mangle]
pub static AEGIS_SPHINX_PACKET_LEN: u32 = SPHINX_PACKET_LEN as u32;

#[no_mangle]
pub static AEGIS_DUDECT_REPLAY_CAPACITY: u32 = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_lab_class_split() {
        assert_eq!(aegis_dudect_replay_lab_init(64), 0);
        assert_eq!(aegis_ct_contains(0), 0);
        assert_eq!(aegis_ct_contains(1), 1);
    }

    #[test]
    fn mac_lab_class_split() {
        aegis_dudect_mac_lab_init();
        assert_eq!(aegis_ct_verify_mac(1), 1);
        assert_eq!(aegis_ct_verify_mac(0), 0);
    }
}
