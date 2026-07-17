//! EWMA reputation scoring (spec §4.8: "ZK reputation (scoped, non-PQ)").
//!
//! This module implements the actual score bookkeeping — real, deterministic,
//! fully tested. It is deliberately NOT zero-knowledge; see [`crate::zk`] for
//! where privacy would be layered on top in a future pass.
//!
//! ## Persistence and operator attestation
//!
//! In-memory [`ReputationLedger::record_success`] / [`ReputationLedger::record_failure`]
//! stay unsigned (local process bookkeeping). Anti-repudiation applies at the
//! **persistence boundary**: optional Ed25519 signatures over a canonical encoding
//! of `(decay, scores)`.
//!
//! - **Unsigned path (default):** [`save_to_file`] / [`load_from_file`] with no
//!   verifying key — same JSON as before (`signature` / `signer_pubkey` omitted).
//! - **Signed path:** [`save_to_file_signed`] attaches an operator signature;
//!   [`load_from_file_verified`] rejects missing, malformed, or tampered signatures
//!   when a verifying key is configured.
//!
//! There is no cross-node consensus; each operator attests only their own snapshot.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const LEDGER_FILE_VERSION: u32 = 1;
/// Domain separator for ledger snapshot signatures.
const LEDGER_SIG_DOMAIN: &[u8] = b"AEGIS-REPUTATION-LEDGER-v1";

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
    #[error("ledger signature missing (verifying key configured)")]
    MissingSignature,
    #[error("ledger signature invalid or signer mismatch")]
    InvalidSignature,
    #[error("invalid operator key material: {0}")]
    InvalidKey(&'static str),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ReputationLedgerFile {
    version: u32,
    decay: f64,
    scores: HashMap<String, f64>,
    /// Hex-encoded Ed25519 signature over [`canonical_ledger_bytes`].
    /// Absent on the unsigned persistence path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    /// Hex-encoded Ed25519 verifying key that produced `signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer_pubkey: Option<String>,
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

    /// Persist scores to unsigned JSON at `path` (single-node local store; no consensus).
    ///
    /// When no operator signing key is configured, this is the production default.
    pub fn save_to_file(&self, path: &Path) -> Result<(), ReputationError> {
        self.write_file(path, None)
    }

    /// Persist scores with an Ed25519 operator attestation over the canonical snapshot.
    pub fn save_to_file_signed(
        &self,
        path: &Path,
        signing_key: &SigningKey,
    ) -> Result<(), ReputationError> {
        self.write_file(path, Some(signing_key))
    }

    fn write_file(
        &self,
        path: &Path,
        signing_key: Option<&SigningKey>,
    ) -> Result<(), ReputationError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let scores: HashMap<String, f64> = self
            .scores
            .iter()
            .map(|(relay, score)| (hex_encode_relay(relay), *score))
            .collect();
        let (signature, signer_pubkey) = if let Some(sk) = signing_key {
            let msg = canonical_ledger_bytes(LEDGER_FILE_VERSION, self.decay, &scores);
            let sig = sk.sign(&msg);
            (
                Some(hex_encode_bytes(&sig.to_bytes())),
                Some(hex_encode_bytes(&sk.verifying_key().to_bytes())),
            )
        } else {
            (None, None)
        };
        let file = ReputationLedgerFile {
            version: LEDGER_FILE_VERSION,
            decay: self.decay,
            scores,
            signature,
            signer_pubkey,
        };
        let text = serde_json::to_string_pretty(&file)?;
        fs::write(path, text)?;
        Ok(())
    }

    /// Load a ledger from JSON; rejects files whose `decay` differs from `expected_decay`.
    ///
    /// Does **not** verify a signature even if present. Use
    /// [`Self::load_from_file_verified`] when an operator verifying key is configured.
    pub fn load_from_file(path: &Path, expected_decay: f64) -> Result<Self, ReputationError> {
        Self::load_from_file_with_verify(path, expected_decay, None)
    }

    /// Load a ledger and verify the operator Ed25519 signature against `verifying_key`.
    ///
    /// Rejects missing signatures, wrong signer pubkeys, and tampered score/decay data.
    pub fn load_from_file_verified(
        path: &Path,
        expected_decay: f64,
        verifying_key: &VerifyingKey,
    ) -> Result<Self, ReputationError> {
        Self::load_from_file_with_verify(path, expected_decay, Some(verifying_key))
    }

    fn load_from_file_with_verify(
        path: &Path,
        expected_decay: f64,
        verifying_key: Option<&VerifyingKey>,
    ) -> Result<Self, ReputationError> {
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
        if let Some(vk) = verifying_key {
            verify_ledger_file(&file, vk)?;
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

/// Canonical bytes signed by the operator: domain || version LE || decay bits LE ||
/// sorted `(relay_id_bytes || score_bits LE)` entries.
fn canonical_ledger_bytes(version: u32, decay: f64, scores: &HashMap<String, f64>) -> Vec<u8> {
    let mut pairs: Vec<(String, f64)> = scores.iter().map(|(k, v)| (k.clone(), *v)).collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::with_capacity(
        LEDGER_SIG_DOMAIN.len() + 4 + 8 + pairs.len().saturating_mul(32 + 8),
    );
    out.extend_from_slice(LEDGER_SIG_DOMAIN);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&decay.to_bits().to_le_bytes());
    for (hex, score) in pairs {
        // Best-effort: skip malformed keys in canonicalization only when building
        // from already-validated file content; callers always pass hex relay ids.
        if let Ok(relay) = parse_hex_relay(&hex) {
            out.extend_from_slice(&relay);
            out.extend_from_slice(&score.to_bits().to_le_bytes());
        }
    }
    out
}

fn verify_ledger_file(
    file: &ReputationLedgerFile,
    verifying_key: &VerifyingKey,
) -> Result<(), ReputationError> {
    let sig_hex = file
        .signature
        .as_deref()
        .ok_or(ReputationError::MissingSignature)?;
    let pk_hex = file
        .signer_pubkey
        .as_deref()
        .ok_or(ReputationError::MissingSignature)?;
    let pk_bytes = parse_hex32(pk_hex).map_err(|_| ReputationError::InvalidSignature)?;
    if pk_bytes != verifying_key.to_bytes() {
        return Err(ReputationError::InvalidSignature);
    }
    let sig_bytes = parse_hex64(sig_hex).map_err(|_| ReputationError::InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);
    let msg = canonical_ledger_bytes(file.version, file.decay, &file.scores);
    verifying_key
        .verify(&msg, &sig)
        .map_err(|_| ReputationError::InvalidSignature)
}

/// Build an Ed25519 signing key from a 32-byte seed.
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Parse a 32-byte hex verifying key.
pub fn verifying_key_from_hex(hex: &str) -> Result<VerifyingKey, ReputationError> {
    let bytes = parse_hex32(hex)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ReputationError::InvalidKey("verifying key"))
}

/// Parse a 32-byte hex seed into a signing key.
pub fn signing_key_from_hex_seed(hex: &str) -> Result<SigningKey, ReputationError> {
    let seed = parse_hex32(hex)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn hex_encode_relay(relay: &[u8; 32]) -> String {
    hex_encode_bytes(relay)
}

fn hex_encode_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex_relay(s: &str) -> Result<[u8; 32], ReputationError> {
    parse_hex32(s).map_err(|e| match e {
        ReputationError::InvalidKey(_) => ReputationError::InvalidRelayId(s.to_string()),
        other => other,
    })
}

fn parse_hex32(s: &str) -> Result<[u8; 32], ReputationError> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 {
        return Err(ReputationError::InvalidKey("expected 64 hex chars"));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if chunk.len() != 2 {
            return Err(ReputationError::InvalidKey("odd hex length"));
        }
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn parse_hex64(s: &str) -> Result<[u8; 64], ReputationError> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 128 {
        return Err(ReputationError::InvalidKey("expected 128 hex chars"));
    }
    let mut out = [0u8; 64];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        if chunk.len() != 2 {
            return Err(ReputationError::InvalidKey("odd hex length"));
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
        _ => Err(ReputationError::InvalidKey("invalid hex digit")),
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

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "aegis-trust-ledger-{label}-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
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
        let dir = temp_dir("roundtrip");
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
        let dir = temp_dir("mismatch");
        let path = dir.join("ledger.json");
        let file = ReputationLedgerFile {
            version: LEDGER_FILE_VERSION,
            decay: 0.8,
            scores: HashMap::new(),
            signature: None,
            signer_pubkey: None,
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

    #[test]
    fn signed_save_and_verified_load_roundtrip() {
        let seed = [0x42u8; 32];
        let sk = signing_key_from_seed(&seed);
        let vk = sk.verifying_key();

        let mut ledger = ReputationLedger::new(0.9).unwrap();
        ledger.admit_new_relay(relay(1));
        ledger.record_success(relay(1));
        ledger.record_failure(relay(2));

        let dir = temp_dir("signed");
        let path = dir.join("ledger.json");
        ledger.save_to_file_signed(&path, &sk).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("signature"));
        assert!(text.contains("signer_pubkey"));

        let loaded = ReputationLedger::load_from_file_verified(&path, 0.9, &vk).unwrap();
        assert_eq!(loaded.score(relay(1)).0, ledger.score(relay(1)).0);
        assert_eq!(loaded.score(relay(2)).0, ledger.score(relay(2)).0);

        // Unsigned load still works for signed files.
        let unsigned = ReputationLedger::load_from_file(&path, 0.9).unwrap();
        assert_eq!(unsigned.score(relay(1)).0, ledger.score(relay(1)).0);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn verified_load_rejects_tampered_scores() {
        let seed = [0x11u8; 32];
        let sk = signing_key_from_seed(&seed);
        let vk = sk.verifying_key();

        let mut ledger = ReputationLedger::new(0.9).unwrap();
        ledger.record_success(relay(1));

        let dir = temp_dir("tamper");
        let path = dir.join("ledger.json");
        ledger.save_to_file_signed(&path, &sk).unwrap();

        let mut file: ReputationLedgerFile =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let key = hex_encode_relay(&relay(1));
        *file.scores.get_mut(&key).unwrap() = 0.99;
        std::fs::write(&path, serde_json::to_string_pretty(&file).unwrap()).unwrap();

        let err = ReputationLedger::load_from_file_verified(&path, 0.9, &vk).unwrap_err();
        assert!(matches!(err, ReputationError::InvalidSignature));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn verified_load_rejects_unsigned_file() {
        let seed = [0x22u8; 32];
        let vk = signing_key_from_seed(&seed).verifying_key();

        let ledger = ReputationLedger::new(0.9).unwrap();
        let dir = temp_dir("unsigned-reject");
        let path = dir.join("ledger.json");
        ledger.save_to_file(&path).unwrap();

        let err = ReputationLedger::load_from_file_verified(&path, 0.9, &vk).unwrap_err();
        assert!(matches!(err, ReputationError::MissingSignature));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn verified_load_rejects_wrong_operator_key() {
        let sk = signing_key_from_seed(&[0x33u8; 32]);
        let other_vk = signing_key_from_seed(&[0x44u8; 32]).verifying_key();

        let mut ledger = ReputationLedger::new(0.9).unwrap();
        ledger.record_failure(relay(9));

        let dir = temp_dir("wrong-key");
        let path = dir.join("ledger.json");
        ledger.save_to_file_signed(&path, &sk).unwrap();

        let err = ReputationLedger::load_from_file_verified(&path, 0.9, &other_vk).unwrap_err();
        assert!(matches!(err, ReputationError::InvalidSignature));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
