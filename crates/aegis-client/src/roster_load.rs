//! Production roster JSON load with consortium signature re-verify.

use std::path::Path;

use aegis_topology::{RelayRoster, RosterError, ThresholdConsortium};
use serde::Deserialize;
use thiserror::Error;

/// TOML `[roster]` section for client configs.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RosterFileConfig {
    /// Path to persisted roster JSON.
    pub path: String,
    /// Hex-encoded Ed25519 consortium verifying keys (32 bytes each).
    #[serde(default)]
    pub authority_pubkeys: Vec<String>,
    /// M-of-N threshold over `authority_pubkeys` (default 1).
    #[serde(default = "default_roster_threshold")]
    pub threshold: usize,
    /// Lab/test only: allow loading without re-verifying when no keys are set.
    /// Ignored when `authority_pubkeys` is non-empty (keys always force verify).
    #[serde(default)]
    pub allow_unverified_roster: bool,
}

fn default_roster_threshold() -> usize {
    1
}

#[derive(Debug, Error)]
pub enum RosterLoadError {
    #[error("hex: {0}")]
    Hex(&'static str),
    #[error("roster: {0}")]
    Roster(#[from] RosterError),
}

/// Load roster JSON using production verification policy.
pub fn load_roster_from_config(cfg: &RosterFileConfig) -> Result<RelayRoster, RosterLoadError> {
    load_roster_from_config_at(Path::new(&cfg.path), cfg)
}

fn load_roster_from_config_at(
    path: &Path,
    cfg: &RosterFileConfig,
) -> Result<RelayRoster, RosterLoadError> {
    let consortium = if cfg.authority_pubkeys.is_empty() {
        None
    } else {
        let mut keys = Vec::with_capacity(cfg.authority_pubkeys.len());
        for hex in &cfg.authority_pubkeys {
            keys.push(parse_hex32(hex)?);
        }
        Some(ThresholdConsortium::from_raw_pubkeys(cfg.threshold, &keys)?)
    };
    Ok(RelayRoster::load_from_file_with_policy(
        path,
        consortium.as_ref(),
        cfg.allow_unverified_roster,
    )?)
}

fn parse_hex32(s: &str) -> Result<[u8; 32], RosterLoadError> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 {
        return Err(RosterLoadError::Hex("expected 64 hex chars for 32 bytes"));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if chunk.len() != 2 {
            return Err(RosterLoadError::Hex("odd hex length"));
        }
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, RosterLoadError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(RosterLoadError::Hex("invalid hex digit")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_topology::{
        test_relay_record, ConsortiumKey, RelayRoster, RosterAdmissionPolicy,
    };
    use aegis_trust::reputation::ReputationLedger;
    use rand_core::OsRng;

    fn hex32(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn rejects_missing_keys_without_lab_flag() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-client-roster-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roster.json");
        RelayRoster::new().save_to_file(&path).unwrap();

        let cfg = RosterFileConfig {
            path: path.to_string_lossy().into(),
            authority_pubkeys: vec![],
            threshold: 1,
            allow_unverified_roster: false,
        };
        let err = load_roster_from_config(&cfg).unwrap_err();
        assert!(matches!(
            err,
            RosterLoadError::Roster(RosterError::UnverifiedRosterNotAllowed)
        ));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn verifies_when_authority_key_configured() {
        let mut rng = OsRng;
        let authority = ConsortiumKey::generate(&mut rng);
        let pk = authority.verifying_key();
        let pk_bytes = pk.to_bytes();

        let mut roster =
            RelayRoster::with_admission_policy(RosterAdmissionPolicy::permissive_for_tests());
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        let signed = authority.sign_record(&test_relay_record(1, "US"));
        roster.admit_signed(signed, &pk, &mut ledger).unwrap();

        let dir = std::env::temp_dir().join(format!(
            "aegis-client-roster-ok-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roster.json");
        roster.save_to_file(&path).unwrap();

        let cfg = RosterFileConfig {
            path: path.to_string_lossy().into(),
            authority_pubkeys: vec![hex32(&pk_bytes)],
            threshold: 1,
            allow_unverified_roster: false,
        };
        let loaded = load_roster_from_config(&cfg).expect("verified load");
        assert_eq!(loaded.len(), 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
