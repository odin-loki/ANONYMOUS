//! Local / file-backed reputation nullifier registry.
//!
//! Records spent [`crate::zk::ReputationNullifier`] values **per epoch** so a
//! verifier process can reject presentation replay. This is **not** a
//! cross-node consensus ledger and **not** an anonymous-credential issuer —
//! see `docs/ops/anonymous_reputation.md`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::zk::ReputationNullifier;

const REGISTRY_FILE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum NullifierError {
    #[error("nullifier already used in epoch {epoch}")]
    AlreadyUsed { epoch: u64 },
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported nullifier registry version {0}")]
    UnsupportedVersion(u32),
    #[error("invalid nullifier hex in registry file: {0}")]
    InvalidNullifierHex(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NullifierRegistryFile {
    version: u32,
    /// Epoch (decimal string key) → hex-encoded nullifiers spent in that epoch.
    epochs: HashMap<String, Vec<String>>,
}

/// In-memory + optional file-backed set of spent reputation nullifiers.
///
/// Scope is intentionally local to one node/process. Double-spend detection
/// across operators requires an external shared ledger (not shipped here).
#[derive(Debug, Clone, Default)]
pub struct NullifierRegistry {
    used: HashMap<u64, HashSet<ReputationNullifier>>,
}

impl NullifierRegistry {
    /// Empty registry (no spent nullifiers).
    pub fn new() -> Self {
        Self {
            used: HashMap::new(),
        }
    }

    /// Load from JSON if `path` exists; otherwise return an empty registry.
    pub fn open_or_empty(path: &Path) -> Result<Self, NullifierError> {
        if path.exists() {
            Self::load_from_file(path)
        } else {
            Ok(Self::new())
        }
    }

    /// Whether `nullifier` was already registered for `epoch`.
    pub fn is_spent(&self, epoch: u64, nullifier: &ReputationNullifier) -> bool {
        self.used
            .get(&epoch)
            .is_some_and(|set| set.contains(nullifier))
    }

    /// Number of spent nullifiers recorded for `epoch`.
    pub fn epoch_len(&self, epoch: u64) -> usize {
        self.used.get(&epoch).map_or(0, HashSet::len)
    }

    /// Total spent nullifiers across all epochs.
    pub fn len(&self) -> usize {
        self.used.values().map(HashSet::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record a nullifier as spent for `epoch`.
    ///
    /// Returns [`NullifierError::AlreadyUsed`] on replay within the same epoch.
    pub fn try_register(
        &mut self,
        epoch: u64,
        nullifier: ReputationNullifier,
    ) -> Result<(), NullifierError> {
        let set = self.used.entry(epoch).or_default();
        if !set.insert(nullifier) {
            return Err(NullifierError::AlreadyUsed { epoch });
        }
        Ok(())
    }

    /// Drop all nullifiers for `epoch` (operator epoch rollover / GC).
    pub fn forget_epoch(&mut self, epoch: u64) {
        self.used.remove(&epoch);
    }

    /// Persist to JSON at `path` (creates parent directories as needed).
    pub fn save_to_file(&self, path: &Path) -> Result<(), NullifierError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut epochs = HashMap::with_capacity(self.used.len());
        for (epoch, set) in &self.used {
            let mut hexes: Vec<String> = set.iter().map(hex_encode_32).collect();
            hexes.sort_unstable();
            epochs.insert(epoch.to_string(), hexes);
        }
        let file = NullifierRegistryFile {
            version: REGISTRY_FILE_VERSION,
            epochs,
        };
        let text = serde_json::to_string_pretty(&file)?;
        fs::write(path, text)?;
        Ok(())
    }

    /// Load a registry from JSON written by [`Self::save_to_file`].
    pub fn load_from_file(path: &Path) -> Result<Self, NullifierError> {
        let text = fs::read_to_string(path)?;
        let file: NullifierRegistryFile = serde_json::from_str(&text)?;
        if file.version != REGISTRY_FILE_VERSION {
            return Err(NullifierError::UnsupportedVersion(file.version));
        }
        let mut used = HashMap::with_capacity(file.epochs.len());
        for (epoch_str, hexes) in file.epochs {
            let epoch: u64 = epoch_str
                .parse()
                .map_err(|_| NullifierError::InvalidNullifierHex(epoch_str.clone()))?;
            let mut set = HashSet::with_capacity(hexes.len());
            for hex in hexes {
                set.insert(parse_hex_32(&hex)?);
            }
            used.insert(epoch, set);
        }
        Ok(Self { used })
    }
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex_32(s: &str) -> Result<[u8; 32], NullifierError> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(NullifierError::InvalidNullifierHex(s.to_string()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0]).map_err(|_| {
            NullifierError::InvalidNullifierHex(s.to_string())
        })?;
        let lo = hex_nibble(chunk[1]).map_err(|_| {
            NullifierError::InvalidNullifierHex(s.to_string())
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::derive_reputation_nullifier;

    #[test]
    fn register_rejects_replay_same_epoch() {
        let mut reg = NullifierRegistry::new();
        let n = derive_reputation_nullifier(&[1u8; 32], 7, &[2u8; 32]);
        assert!(reg.try_register(7, n).is_ok());
        assert!(reg.is_spent(7, &n));
        assert!(matches!(
            reg.try_register(7, n),
            Err(NullifierError::AlreadyUsed { epoch: 7 })
        ));
    }

    #[test]
    fn same_nullifier_allowed_in_different_epoch() {
        let mut reg = NullifierRegistry::new();
        let n = derive_reputation_nullifier(&[1u8; 32], 1, &[2u8; 32]);
        assert!(reg.try_register(1, n).is_ok());
        // Policy may re-derive with a new epoch; registry keys by epoch.
        assert!(reg.try_register(2, n).is_ok());
        assert_eq!(reg.epoch_len(1), 1);
        assert_eq!(reg.epoch_len(2), 1);
    }

    #[test]
    fn forget_epoch_clears_spend_set() {
        let mut reg = NullifierRegistry::new();
        let n = [9u8; 32];
        reg.try_register(3, n).unwrap();
        reg.forget_epoch(3);
        assert!(!reg.is_spent(3, &n));
        assert!(reg.try_register(3, n).is_ok());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-nullifier-reg-{}",
            std::process::id()
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("nullifiers.json");

        let mut reg = NullifierRegistry::new();
        let a = derive_reputation_nullifier(&[1u8; 32], 10, &[3u8; 32]);
        let b = derive_reputation_nullifier(&[2u8; 32], 10, &[4u8; 32]);
        let c = derive_reputation_nullifier(&[1u8; 32], 11, &[3u8; 32]);
        reg.try_register(10, a).unwrap();
        reg.try_register(10, b).unwrap();
        reg.try_register(11, c).unwrap();
        reg.save_to_file(&path).unwrap();

        let loaded = NullifierRegistry::load_from_file(&path).unwrap();
        assert!(loaded.is_spent(10, &a));
        assert!(loaded.is_spent(10, &b));
        assert!(loaded.is_spent(11, &c));
        assert!(!loaded.is_spent(11, &a));
        assert_eq!(loaded.len(), 3);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn open_or_empty_missing_path() {
        let path = std::env::temp_dir().join(format!(
            "aegis-nullifier-missing-{}",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let reg = NullifierRegistry::open_or_empty(&path).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn load_rejects_unsupported_version() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-nullifier-ver-{}",
            std::process::id()
        ));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("bad.json");
        fs::write(
            &path,
            r#"{"version":99,"epochs":{}}"#,
        )
        .unwrap();
        assert!(matches!(
            NullifierRegistry::load_from_file(&path),
            Err(NullifierError::UnsupportedVersion(99))
        ));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }
}
