//! Consortium key-ceremony helpers (ops).
//!
//! Used by `aegis-ceremony` and unit tests. See `docs/ops/consortium_key_ceremony.md`.

use std::fs;
use std::path::{Path, PathBuf};

use aegis_crypto::kem::RelayKemSecret;
use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use serde::Serialize;

use crate::error::RosterError;
use crate::roster::{ConsortiumKey, ThresholdConsortium, ThresholdSignedRelayRecord};
use crate::shamir::{
    decode_share_hex, encode_share_hex, reconstruct_seed, split_seed, SeedShare,
};
use crate::types::{JurisdictionId, RelayRecord};

/// Parameters for a local M-of-N key ceremony.
#[derive(Clone, Debug)]
pub struct CeremonyConfig {
    pub n: usize,
    pub threshold: usize,
    pub jurisdiction: String,
    /// Write full authority signing seeds as hex (lab only).
    pub write_seeds: bool,
    /// Optional Shamir share count per authority seed (`None` = no Shamir).
    pub shamir_n: Option<usize>,
    /// Optional Shamir reconstruction threshold (`None` = no Shamir).
    pub shamir_threshold: Option<usize>,
}

impl Default for CeremonyConfig {
    fn default() -> Self {
        Self {
            n: 3,
            threshold: 2,
            jurisdiction: "US".into(),
            write_seeds: true,
            shamir_n: None,
            shamir_threshold: None,
        }
    }
}

/// Result of [`run_ceremony`].
#[derive(Clone, Debug)]
pub struct CeremonyOutput {
    pub authority_pubkeys_hex: Vec<String>,
    pub sample_admission: ThresholdSignedRelayRecord,
    pub consortium: ThresholdConsortium,
    /// Per-authority Shamir share paths when Shamir was enabled.
    pub shamir_share_paths: Vec<Vec<PathBuf>>,
}

#[derive(Serialize)]
struct ConsortiumManifest {
    threshold: usize,
    n: usize,
    authority_pubkeys_hex: Vec<String>,
    sample_admission_path: String,
    shamir_n: Option<usize>,
    shamir_threshold: Option<usize>,
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
///
/// When `shamir_n` / `shamir_threshold` are set, each authority seed is split into
/// Shamir M-of-N shares written under `authorities/authority-{i}/share-{j}.hex`
/// (share files only — distribute to distinct custodians).
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

    let shamir_enabled = cfg.shamir_n.is_some() || cfg.shamir_threshold.is_some();
    let (shamir_n, shamir_t) = if shamir_enabled {
        let sn = cfg
            .shamir_n
            .ok_or_else(|| "shamir_n required when enabling Shamir".to_string())?;
        let st = cfg
            .shamir_threshold
            .ok_or_else(|| "shamir_threshold required when enabling Shamir".to_string())?;
        if st == 0 || st > sn {
            return Err(format!(
                "shamir_threshold must be in 1..={sn} (got {st})"
            ));
        }
        if sn > 255 {
            return Err("shamir_n must be <= 255".into());
        }
        (Some(sn), Some(st))
    } else {
        (None, None)
    };

    fs::create_dir_all(out_dir).map_err(|e| format!("create out dir: {e}"))?;
    let keys_dir = out_dir.join("authorities");
    fs::create_dir_all(&keys_dir).map_err(|e| format!("create authorities dir: {e}"))?;

    let mut keys = Vec::with_capacity(cfg.n);
    let mut pubkeys_hex = Vec::with_capacity(cfg.n);
    let mut shamir_share_paths = Vec::with_capacity(cfg.n);

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

        let mut paths_for_auth = Vec::new();
        if let (Some(sn), Some(st)) = (shamir_n, shamir_t) {
            let shares = split_seed(&seed, st, sn, rng).map_err(|e| e.to_string())?;
            let share_dir = keys_dir.join(format!("authority-{i}"));
            fs::create_dir_all(&share_dir).map_err(|e| e.to_string())?;
            for (j, share) in shares.iter().enumerate() {
                let path = share_dir.join(format!("share-{j}.hex"));
                write_restricted(&path, format!("{}\n", encode_share_hex(share)).as_bytes())?;
                paths_for_auth.push(path);
            }
        }
        shamir_share_paths.push(paths_for_auth);
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
    write_restricted(
        out_dir.join("sample_admission.json").as_path(),
        admission_json.as_bytes(),
    )?;

    let note = if shamir_n.is_some() {
        "Distribute .pub.hex to operators; keep full .seed.hex offline if written. Distribute each Shamir share-*.hex to a distinct custodian; reconstruct with reconstruct_seed_from_files before signing.".into()
    } else {
        "Distribute .pub.hex to operators; keep .seed.hex offline (HSM/airgap). Configure node [roster] authority_pubkeys + threshold from pubkeys.".into()
    };

    let manifest = ConsortiumManifest {
        threshold: cfg.threshold,
        n: cfg.n,
        authority_pubkeys_hex: pubkeys_hex.clone(),
        sample_admission_path: "sample_admission.json".into(),
        shamir_n,
        shamir_threshold: shamir_t,
        note,
    };
    let manifest_json =
        serde_json::to_string_pretty(&manifest).map_err(|e| format!("serialize manifest: {e}"))?;
    write_restricted(
        out_dir.join("consortium.json").as_path(),
        manifest_json.as_bytes(),
    )?;

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
        shamir_share_paths,
    })
}

/// Lab helper: reconstruct a 32-byte authority seed from Shamir share hex files.
pub fn reconstruct_seed_from_files(paths: &[PathBuf]) -> Result<[u8; 32], String> {
    if paths.is_empty() {
        return Err("need at least one share file".into());
    }
    let mut shares = Vec::with_capacity(paths.len());
    for path in paths {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        shares.push(decode_share_hex(&text)?);
    }
    reconstruct_seed(&shares).map_err(|e| e.to_string())
}

/// Lab helper: reconstruct from in-memory shares.
pub fn reconstruct_authority_seed(shares: &[SeedShare]) -> Result<[u8; 32], String> {
    reconstruct_seed(shares).map_err(|e| e.to_string())
}

/// Write a reconstructed seed to a restricted hex file (lab).
pub fn write_reconstructed_seed(path: &Path, seed: &[u8; 32]) -> Result<(), String> {
    write_restricted(path, format!("{}\n", hex_encode(seed)).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-ceremony-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn ceremony_writes_verified_m_of_n_admission() {
        let dir = temp_dir("basic");
        let _ = fs::remove_dir_all(&dir);

        let cfg = CeremonyConfig {
            n: 3,
            threshold: 2,
            jurisdiction: "DE".into(),
            write_seeds: true,
            ..CeremonyConfig::default()
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
        let dir = temp_dir("bad-threshold");
        let cfg = CeremonyConfig {
            n: 2,
            threshold: 3,
            ..CeremonyConfig::default()
        };
        assert!(run_ceremony(&dir, &cfg, &mut OsRng).is_err());
    }

    #[test]
    fn ceremony_shamir_shares_reconstruct_to_seed() {
        let dir = temp_dir("shamir");
        let _ = fs::remove_dir_all(&dir);

        let cfg = CeremonyConfig {
            n: 2,
            threshold: 2,
            jurisdiction: "US".into(),
            write_seeds: true,
            shamir_n: Some(3),
            shamir_threshold: Some(2),
        };
        let out = run_ceremony(&dir, &cfg, &mut OsRng).expect("ceremony");
        assert_eq!(out.shamir_share_paths.len(), 2);
        assert_eq!(out.shamir_share_paths[0].len(), 3);

        let seed_hex = fs::read_to_string(
            dir.join("authorities").join("authority-0.seed.hex"),
        )
        .unwrap();
        let expected = hex_decode_32(seed_hex.trim()).unwrap();

        let paths = &out.shamir_share_paths[0][0..2];
        let rec = reconstruct_seed_from_files(paths).expect("reconstruct");
        assert_eq!(rec, expected);

        // Different pair of shares.
        let paths2 = vec![
            out.shamir_share_paths[0][0].clone(),
            out.shamir_share_paths[0][2].clone(),
        ];
        assert_eq!(reconstruct_seed_from_files(&paths2).unwrap(), expected);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ceremony_shamir_requires_both_params() {
        let dir = temp_dir("shamir-partial");
        let cfg = CeremonyConfig {
            shamir_n: Some(3),
            shamir_threshold: None,
            ..CeremonyConfig::default()
        };
        assert!(run_ceremony(&dir, &cfg, &mut OsRng).is_err());
    }

    fn hex_decode_32(hex: &str) -> Result<[u8; 32], String> {
        if hex.len() != 64 {
            return Err("expected 64 hex chars".into());
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
        }
        Ok(out)
    }
}
