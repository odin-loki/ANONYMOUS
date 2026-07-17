#![no_main]

use aegis_topology::roster::{RelayRoster, SignedRelayRecord};
use ed25519_dalek::VerifyingKey;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Untrusted consortium roster JSON (single signed record).
    let signed: Result<SignedRelayRecord, _> = serde_json::from_slice(data);
    if let Ok(record) = &signed {
        if let Ok(pk) = VerifyingKey::from_bytes(&record.authority_pubkey) {
            let _ = record.verify(&pk);
        }
    }

    // Untrusted persisted roster file bytes (admin-distributed JSON on disk).
    let path = std::env::temp_dir().join(format!(
        "aegis-fuzz-roster-{}-{}",
        std::process::id(),
        data.len()
    ));
    if std::fs::write(&path, data).is_ok() {
        // Exercise unverified deserialize + optional verified path (None = skip verify).
        let _ = RelayRoster::load_from_file_unverified(&path);
        let _ = RelayRoster::load_from_file_with_policy(&path, None, true);
        let _ = std::fs::remove_file(&path);
    }
});
