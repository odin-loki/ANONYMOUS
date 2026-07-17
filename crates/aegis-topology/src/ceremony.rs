//! Consortium key-ceremony helpers (ops).
//!
//! Used by `aegis-ceremony` and unit tests. See `docs/ops/consortium_key_ceremony.md`.

use std::fs;
use std::path::Path;

use aegis_crypto::kem::RelayKemSecret;
use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;

use crate::error::RosterError;
use crate::roster::{
    ConsortiumKey, ThresholdConsortium, ThresholdSignedRelayRecord,
};
use crate::types::{JurisdictionId, RelayRecord};

/// Parameters for a local M-of-N key ceremony.
#[derive(Clone, Debug)]
pub struct CeremonyConfig {
    pub n: usize,
    pub threshold: usize,
    pub jurisdiction: String,
    pub write_seeds: bool,
}

impl Default for CeremonyConfig {
    fn default() -> Self {
        Self {
            n: 3,
            threshold: 2,
            jurisdiction: "US".into(),
            write_seeds: true,
        }
    }
}

/// Result of [`run_ceremony`].
#[derive(Clone, Debug)]
pub struct CeremonyOutput {
    pub authority_pubkeys_hex: Vec<String>,
    pub sample_admission: ThresholdSignedRelayRecord,
    pub consortium: ThresholdConsortium,
}

#[derive(Serialize)]
struct ConsortiumManifest {
    threshold: usize,
    n: usize,
    authority_pubkeys_hex: Vec<String>,
    sample_admission_path: String,
    note: String,
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_restricted(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.write_all(contents).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents).map_err(|e| e.to_string())
    }
}

/// Generate N authority keys, write artifacts under `out_dir`, and return a verified sample admission.
pub fn run_ceremony(
    out_dir: &Path,
    cfg: &CeremonyConfig,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<CeremonyOutput, String> {
    if cfg.n == 0 {
        return Err("n must be >= 1".into());
    }
    if cfg.threshold == 0 || cfg.threshold > cfg.n {
        return Err(format!(
            "threshold must be in 1..={} (got {})",
            cfg.n, cfg.threshold
        ));
    }

    fs::create_dir_all(out_dir).map_err(|e| format!("create out dir: {e}"))?;
    let keys_dir = out_dir.join("authorities");
    fs::create_dir_all(&keys_dir).map_err(|e| format!("create authorities dir: {e}"))?;

    let mut keys = Vec::with_capacity(cfg.n);
    let mut pubkeys_hex = Vec::with_capacity(cfg.n);

    for i in 0..cfg.n {
        let sk = SigningKey::generate(rng);
        let seed = sk.to_bytes();
        let key = ConsortiumKey::from_signing_key(sk);
        let pk_hex = hex_encode(&key.verifying_key().to_bytes());
        pubkeys_hex.push(pk_hex.clone());

        write_restricted(
            &keys_dir.join(format!("authority-{i}.pub.hex")),
            format!("{pk_hex}\n").as_bytes(),
        )?;
        if cfg.write_seeds {
            write_restricted(
                &keys_dir.join(format!("authority-{i}.seed.hex")),
                format!("{}\n", hex_encode(&seed)).as_bytes(),
            )?;
        }
        keys.push(key);
    }

    let consortium = ThresholdConsortium::new(
        cfg.threshold,
        keys.iter().map(|k| k.verifying_key()).collect(),
    )
    .map_err(|e: RosterError| format!("consortium: {e}"))?;

    let (_kem_sec, kem_pk) = RelayKemSecret::generate(rng);
    let record =
        RelayRecord::from_kem_public(JurisdictionId::new(cfg.jurisdiction.clone()), &kem_pk);

    let mut signed = ThresholdSignedRelayRecord::new(record.clone());
    for key in keys.iter().take(cfg.threshold) {
        signed = signed.with_signature(key.sign_authority(&record));
    }
    signed
        .verify_threshold(&consortium)
        .map_err(|e| format!("sample admission verify failed: {e}"))?;

    let admission_json =
        serde_json::to_string_pretty(&signed).map_err(|e| format!("serialize admission: {e}"))?;
    write_restricted(out_dir.join("sample_admission.json").as_path(), admission_json.as_bytes())?;

    let manifest = ConsortiumManifest {
        threshold: cfg.threshold,
        n: cfg.n,
        authority_pubkeys_hex: pubkeys_hex.clone(),
        sample_admission_path: "sample_admission.json".into(),
        note: "Distribute .pub.hex to operators; keep .seed.hex offline (HSM/airgap). Configure node [roster] authority_pubkeys + threshold from pubkeys.".into(),
    };
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("serialize manifest: {e}"))?;
    write_restricted(out_dir.join("consortium.json").as_path(), manifest_json.as_bytes())?;

    let mut toml_snippet = String::from("# Paste into node/client [roster] section\n");
    toml_snippet.push_str(&format!("threshold = {}\n", cfg.threshold));
    toml_snippet.push_str("authority_pubkeys = [\n");
    for pk in &pubkeys_hex {
        toml_snippet.push_str(&format!("  \"{pk}\",\n"));
    }
    toml_snippet.push_str("]\n");
    write_restricted(
        out_dir.join("roster_authority.toml.snippet").as_path(),
        toml_snippet.as_bytes(),
    )?;

    Ok(CeremonyOutput {
        authority_pubkeys_hex: pubkeys_hex,
        sample_admission: signed,
        consortium,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn ceremony_writes_verified_m_of_n_admission() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-ceremony-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);

        let cfg = CeremonyConfig {
            n: 3,
            threshold: 2,
            jurisdiction: "DE".into(),
            write_seeds: true,
        };
        let out = run_ceremony(&dir, &cfg, &mut OsRng).expect("ceremony");
        assert_eq!(out.authority_pubkeys_hex.len(), 3);
        out.sample_admission
            .verify_threshold(&out.consortium)
            .expect("verify");
        assert!(dir.join("sample_admission.json").is_file());
        assert!(dir.join("consortium.json").is_file());
        assert!(dir.join("authorities").join("authority-0.pub.hex").is_file());
        assert!(dir.join("authorities").join("authority-0.seed.hex").is_file());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ceremony_rejects_invalid_threshold() {
        let dir = std::env::temp_dir().join("aegis-ceremony-bad-threshold");
        let cfg = CeremonyConfig {
            n: 2,
            threshold: 3,
            ..CeremonyConfig::default()
        };
        assert!(run_ceremony(&dir, &cfg, &mut OsRng).is_err());
    }
}
