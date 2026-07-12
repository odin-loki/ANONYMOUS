#![no_main]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use aegis_topology::beacon::{ThresholdBeacon, ThresholdBeaconCommittee};
use blsttc::{SignatureShare, SIG_SIZE};
use libfuzzer_sys::fuzz_target;
use rand::thread_rng;

static COMMITTEE: OnceLock<ThresholdBeaconCommittee> = OnceLock::new();

fn committee() -> &'static ThresholdBeaconCommittee {
    COMMITTEE.get_or_init(|| ThresholdBeaconCommittee::dealer_setup(5, 3, &mut thread_rng()))
}

fn share_from_prefix(data: &[u8]) -> Option<SignatureShare> {
    if data.len() < SIG_SIZE {
        return None;
    }
    let mut bytes = [0u8; SIG_SIZE];
    bytes.copy_from_slice(&data[..SIG_SIZE]);
    SignatureShare::from_bytes(bytes).ok()
}

fuzz_target!(|data: &[u8]| {
    let round = if data.len() >= 8 {
        u64::from_le_bytes(data[..8].try_into().expect("8 bytes"))
    } else {
        0
    };

    // Wire-format partial BLS signature bytes from an untrusted threshold participant.
    if let Some(share) = share_from_prefix(data) {
        let index = data.len() % committee().committee_size;
        let mut beacon = ThresholdBeacon::new(committee().pk_set.clone());
        beacon.add_shares(round, [(index, share)]);
        let _ = beacon.randomness_result(round);
    }

    // Batch of malformed shares keyed by participant index (simulates share flood).
    let mut shares = BTreeMap::new();
    for (i, chunk) in data.chunks(SIG_SIZE).enumerate() {
        if let Some(share) = share_from_prefix(chunk) {
            shares.insert(i % committee().committee_size, share);
        }
    }
    if !shares.is_empty() {
        let beacon = ThresholdBeacon::from_quorum(committee().pk_set.clone(), round, shares);
        let _ = beacon.randomness_result(round);
    }
});
