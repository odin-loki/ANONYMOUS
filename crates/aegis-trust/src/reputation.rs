//! EWMA reputation scoring (spec §4.8: "ZK reputation (scoped, non-PQ)").
//!
//! This module implements the actual score bookkeeping — real, deterministic,
//! fully tested. It is deliberately NOT zero-knowledge; see [`crate::zk`] for
//! where privacy would be layered on top in a future pass.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const LEDGER_FILE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ReputationError {
    #[error("decay factor must be in (0, 1], got {0}")]
    InvalidDecay(f64),
    #[error("unknown relay")]
    UnknownRelay,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported ledger file version {0}")]
    UnsupportedVersion(u32),
    #[error("ledger decay mismatch: file has {file_decay}, expected {expected_decay}")]
    DecayMismatch {
        file_decay: f64,
        expected_decay: f64,
    },
    #[error("invalid relay id in ledger file: {0}")]
    InvalidRelayId(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ReputationLedgerFile {
    version: u32,
    decay: f64,
    scores: HashMap<String, f64>,
}

/// A reputation score in `[0.0, 1.0]`; 1.0 = perfect observed behavior so far.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct ReputationScore(pub f64);

impl ReputationScore {
    /// Default for relays with no ledger entry (never admitted via production path).
    pub const NEUTRAL: ReputationScore = ReputationScore(0.5);
    /// Starting score for relays admitted via [`ReputationLedger::admit_new_relay`].
    /// Below the 0.3 reputation floor used by guard/path selection in `aegis-topology`.
    pub const PROBATIONARY: ReputationScore = ReputationScore(0.1);

    fn clamp01(x: f64) -> f64 {
        x.clamp(0.0, 1.0)
    }
}

/// Per-relay EWMA reputation: `score' = decay * score + (1 - decay) * outcome`,
/// `outcome ∈ {0.0 (failure), 1.0 (success)}`. Larger `decay` -> longer memory
/// (slower to punish/forgive); smaller `decay` -> reacts fast to recent behavior.
#[derive(Debug)]
pub struct ReputationLedger {
    decay: f64,
    scores: HashMap<[u8; 32], f64>,
}

impl ReputationLedger {
    /// `decay` in `(0, 1]`. Typical: 0.9–0.99 (slow-moving reputation, resists
    /// single-observation noise, consistent with the consortium/permissioned
    /// model where relays are long-lived, vetted entities, not throwaway Sybils).
    pub fn new(decay: f64) -> Result<Self, ReputationError> {
        Self::from_scores(decay, HashMap::new())
    }

    /// EWMA decay factor configured for this ledger.
    pub fn decay(&self) -> f64 {
        self.decay
    }

    fn from_scores(decay: f64, scores: HashMap<[u8; 32], f64>) -> Result<Self, ReputationError> {
        if !(decay > 0.0 && decay <= 1.0) {
            return Err(ReputationError::InvalidDecay(decay));
        }
        Ok(Self { decay, scores })
    }

    /// Current score, defaulting relays with no ledger entry to [`ReputationScore::NEUTRAL`].
    ///
    /// Relays seeded at admission via [`Self::admit_new_relay`] are not "unseen" — they
    /// return [`ReputationScore::PROBATIONARY`] until real outcomes move the EWMA.
    pub fn score(&self, relay: [u8; 32]) -> ReputationScore {
        ReputationScore(*self.scores.get(&relay).unwrap_or(&ReputationScore::NEUTRAL.0))
    }

    /// Seed a newly-admitted relay at [`ReputationScore::PROBATIONARY`].
    ///
    /// Idempotent when the relay already has a ledger entry (re-admission does not
    /// downgrade an established score).
    pub fn admit_new_relay(&mut self, relay: [u8; 32]) {
        self.scores
            .entry(relay)
            .or_insert(ReputationScore::PROBATIONARY.0);
    }

    fn update(&mut self, relay: [u8; 32], outcome: f64) {
        let prev = *self.scores.get(&relay).unwrap_or(&ReputationScore::NEUTRAL.0);
        let next = ReputationScore::clamp01(self.decay * prev + (1.0 - self.decay) * outcome);
        self.scores.insert(relay, next);
    }

    pub fn record_success(&mut self, relay: [u8; 32]) {
        self.update(relay, 1.0);
    }

    pub fn record_failure(&mut self, relay: [u8; 32]) {
        self.update(relay, 0.0);
    }

    /// One EWMA step from an aggregate success/failure window (`outcome = successes / total`).
    pub fn record_aggregate(&mut self, relay: [u8; 32], successes: u64, failures: u64) {
        let total = successes.saturating_add(failures);
        if total == 0 {
            return;
        }
        let outcome = successes as f64 / total as f64;
        self.update(relay, outcome);
    }

    /// Persist scores to JSON at `path` (single-node local store; no consensus).
    pub fn save_to_file(&self, path: &Path) -> Result<(), ReputationError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let file = ReputationLedgerFile {
            version: LEDGER_FILE_VERSION,
            decay: self.decay,
            scores: self
                .scores
                .iter()
                .map(|(relay, score)| (hex_encode_relay(relay), *score))
                .collect(),
        };
        let text = serde_json::to_string_pretty(&file)?;
        fs::write(path, text)?;
        Ok(())
    }

    /// Load a ledger from JSON; rejects files whose `decay` differs from `expected_decay`.
    pub fn load_from_file(path: &Path, expected_decay: f64) -> Result<Self, ReputationError> {
        let text = fs::read_to_string(path)?;
        let file: ReputationLedgerFile = serde_json::from_str(&text)?;
        if file.version != LEDGER_FILE_VERSION {
            return Err(ReputationError::UnsupportedVersion(file.version));
        }
        if (file.decay - expected_decay).abs() > f64::EPSILON {
            return Err(ReputationError::DecayMismatch {
                file_decay: file.decay,
                expected_decay,
            });
        }
        let mut scores = HashMap::with_capacity(file.scores.len());
        for (hex, score) in file.scores {
            let relay = parse_hex_relay(&hex)?;
            scores.insert(relay, ReputationScore::clamp01(score));
        }
        Self::from_scores(expected_decay, scores)
    }

    /// Relays whose score has fallen below `threshold` — candidates for
    /// de-admission from [`aegis_topology`]'s `RelayRoster` (not wired up
    /// automatically; that integration is a future step, kept as a caller
    /// decision here since de-admission has consortium-governance implications
    /// beyond this crate's scope).
    pub fn below_threshold(&self, threshold: f64) -> Vec<[u8; 32]> {
        self.scores
            .iter()
            .filter(|(_, &s)| s < threshold)
            .map(|(id, _)| *id)
            .collect()
    }
}

fn hex_encode_relay(relay: &[u8; 32]) -> String {
    relay.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex_relay(s: &str) -> Result<[u8; 32], ReputationError> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 {
        return Err(ReputationError::InvalidRelayId(s.to_string()));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if chunk.len() != 2 {
            return Err(ReputationError::InvalidRelayId(s.to_string()));
        }
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, ReputationError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ReputationError::InvalidRelayId(format!("invalid hex digit {b}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn unseen_relay_is_neutral() {
        let ledger = ReputationLedger::new(0.9).unwrap();
        assert_eq!(ledger.score(relay(1)).0, 0.5);
    }

    #[test]
    fn admit_new_relay_starts_probationary() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        ledger.admit_new_relay(relay(1));
        assert_eq!(ledger.score(relay(1)).0, ReputationScore::PROBATIONARY.0);
        assert!(ledger.score(relay(1)).0 < 0.3);
    }

    #[test]
    fn admit_new_relay_does_not_downgrade_existing_score() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        for _ in 0..20 {
            ledger.record_success(relay(1));
        }
        let before = ledger.score(relay(1)).0;
        ledger.admit_new_relay(relay(1));
        assert_eq!(ledger.score(relay(1)).0, before);
    }

    #[test]
    fn probationary_relay_can_earn_above_floor() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        ledger.admit_new_relay(relay(1));
        for _ in 0..50 {
            ledger.record_success(relay(1));
        }
        assert!(ledger.score(relay(1)).0 >= 0.3);
    }

    #[test]
    fn repeated_success_raises_score_toward_one() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        for _ in 0..200 {
            ledger.record_success(relay(1));
        }
        assert!(ledger.score(relay(1)).0 > 0.95);
    }

    #[test]
    fn repeated_failure_lowers_score_toward_zero() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        for _ in 0..200 {
            ledger.record_failure(relay(1));
        }
        assert!(ledger.score(relay(1)).0 < 0.05);
    }

    #[test]
    fn score_stays_in_bounds() {
        let mut ledger = ReputationLedger::new(0.5).unwrap();
        for _ in 0..1000 {
            ledger.record_success(relay(1));
            ledger.record_failure(relay(2));
        }
        assert!((0.0..=1.0).contains(&ledger.score(relay(1)).0));
        assert!((0.0..=1.0).contains(&ledger.score(relay(2)).0));
    }

    #[test]
    fn below_threshold_flags_bad_relays_only() {
        let mut ledger = ReputationLedger::new(0.8).unwrap();
        for _ in 0..50 {
            ledger.record_success(relay(1));
            ledger.record_failure(relay(2));
        }
        let bad = ledger.below_threshold(0.3);
        assert!(bad.contains(&relay(2)));
        assert!(!bad.contains(&relay(1)));
    }

    #[test]
    fn invalid_decay_rejected() {
        assert!(ReputationLedger::new(0.0).is_err());
        assert!(ReputationLedger::new(1.5).is_err());
        assert!(ReputationLedger::new(1.0).is_ok());
    }

    #[test]
    fn record_aggregate_moves_score_toward_success_rate() {
        let mut ledger = ReputationLedger::new(0.5).unwrap();
        // Neutral 0.5, decay 0.5, outcome 0.9 → 0.5*0.5 + 0.5*0.9 = 0.70
        ledger.record_aggregate(relay(1), 9, 1);
        assert!((ledger.score(relay(1)).0 - 0.70).abs() < 1e-9);
        ledger.record_aggregate(relay(1), 0, 10);
        assert!(ledger.score(relay(1)).0 < 0.5);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut ledger = ReputationLedger::new(0.9).unwrap();
        ledger.admit_new_relay(relay(1));
        for _ in 0..10 {
            ledger.record_success(relay(1));
            ledger.record_failure(relay(2));
        }
        let dir = std::env::temp_dir().join(format!(
            "aegis-trust-ledger-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ledger.json");
        ledger.save_to_file(&path).unwrap();
        let loaded = ReputationLedger::load_from_file(&path, 0.9).unwrap();
        assert_eq!(loaded.decay(), 0.9);
        assert_eq!(loaded.score(relay(1)).0, ledger.score(relay(1)).0);
        assert_eq!(loaded.score(relay(2)).0, ledger.score(relay(2)).0);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn load_rejects_decay_mismatch() {
        let dir = std::env::temp_dir().join(format!(
            "aegis-trust-ledger-mismatch-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ledger.json");
        let file = ReputationLedgerFile {
            version: LEDGER_FILE_VERSION,
            decay: 0.8,
            scores: HashMap::new(),
        };
        std::fs::write(&path, serde_json::to_string(&file).unwrap()).unwrap();
        let err = ReputationLedger::load_from_file(&path, 0.9).unwrap_err();
        assert!(matches!(
            err,
            ReputationError::DecayMismatch {
                file_decay,
                expected_decay,
            } if (file_decay - 0.8).abs() < f64::EPSILON && (expected_decay - 0.9).abs() < f64::EPSILON
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
