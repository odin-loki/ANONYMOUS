//! Signed cross-relay peer-health gossip (`PeerHealthAdvert`).
//!
//! Minimal, non-BFT: each relay signs local success/failure counts about a
//! subject peer and exchanges them as link-control cells
//! ([`Command::PeerHealthAdvert`](aegis_crypto::cell::Command::PeerHealthAdvert))
//! that never enter Sphinx reassembly. Receivers verify the Ed25519 signature
//! and accept only from admitted peer-table neighbors.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use aegis_crypto::cell::{Cell, Command, CELL_LEN};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

use crate::peer_health::PeerHealthTracker;
use crate::relay_id::RelayId;

/// Canonical signed body length (no command byte, no signature).
/// `reporter(32) || subject(32) || successes(8) || failures(8) || timestamp(8)`.
pub const ADVERT_BODY_LEN: usize = 32 + 32 + 8 + 8 + 8;

/// Ed25519 signature length.
pub const ADVERT_SIG_LEN: usize = 64;

/// Bytes after the command byte used by a serialized advert.
pub const ADVERT_WIRE_LEN: usize = ADVERT_BODY_LEN + ADVERT_SIG_LEN;

/// Default max age for accepted adverts (seconds).
pub const DEFAULT_MAX_ADVERT_AGE_SECS: u64 = 3600;

/// Gossip outcomes are applied at half weight (simple trust-of-reporter decay).
pub const GOSSIP_WEIGHT_NUM: u64 = 1;
pub const GOSSIP_WEIGHT_DEN: u64 = 2;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HealthGossipError {
    #[error("malformed peer-health advert")]
    Malformed,
    #[error("invalid gossip signature")]
    BadSignature,
    #[error("reporter is not an admitted peer-table neighbor")]
    UnknownReporter,
    #[error("reporter id does not match authenticated link peer")]
    ReporterMismatch,
    #[error("advert timestamp too old or in the far future")]
    StaleTimestamp,
    #[error("missing gossip verifying key for reporter")]
    MissingVerifyingKey,
}

/// Signed report: reporter observed `successes`/`failures` toward `subject`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerHealthAdvert {
    pub reporter: [u8; 32],
    pub subject: [u8; 32],
    pub successes: u64,
    pub failures: u64,
    pub timestamp_secs: u64,
    pub signature: [u8; ADVERT_SIG_LEN],
}

impl PeerHealthAdvert {
    /// Canonical bytes covered by the Ed25519 signature.
    pub fn signable_bytes(&self) -> [u8; ADVERT_BODY_LEN] {
        let mut out = [0u8; ADVERT_BODY_LEN];
        out[0..32].copy_from_slice(&self.reporter);
        out[32..64].copy_from_slice(&self.subject);
        out[64..72].copy_from_slice(&self.successes.to_le_bytes());
        out[72..80].copy_from_slice(&self.failures.to_le_bytes());
        out[80..88].copy_from_slice(&self.timestamp_secs.to_le_bytes());
        out
    }

    /// Build and sign an advert under `signing_key`.
    pub fn sign(
        signing_key: &SigningKey,
        reporter: [u8; 32],
        subject: [u8; 32],
        successes: u64,
        failures: u64,
        timestamp_secs: u64,
    ) -> Self {
        let mut advert = Self {
            reporter,
            subject,
            successes,
            failures,
            timestamp_secs,
            signature: [0u8; ADVERT_SIG_LEN],
        };
        let sig = signing_key.sign(&advert.signable_bytes());
        advert.signature = sig.to_bytes();
        advert
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), HealthGossipError> {
        let sig = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&self.signable_bytes(), &sig)
            .map_err(|_| HealthGossipError::BadSignature)
    }

    /// Encode into a fixed 512-byte cell (`Command::PeerHealthAdvert`).
    pub fn to_cell(&self) -> Cell {
        let mut buf = [0u8; CELL_LEN];
        buf[0] = Command::PeerHealthAdvert as u8;
        buf[1..1 + ADVERT_BODY_LEN].copy_from_slice(&self.signable_bytes());
        buf[1 + ADVERT_BODY_LEN..1 + ADVERT_WIRE_LEN].copy_from_slice(&self.signature);
        Cell::from_bytes(buf)
    }

    /// Parse a cell; does not verify the signature.
    pub fn from_cell(cell: &Cell) -> Result<Self, HealthGossipError> {
        let b = cell.as_bytes();
        if Command::from_u8(b[0]) != Some(Command::PeerHealthAdvert) {
            return Err(HealthGossipError::Malformed);
        }
        let mut reporter = [0u8; 32];
        let mut subject = [0u8; 32];
        reporter.copy_from_slice(&b[1..33]);
        subject.copy_from_slice(&b[33..65]);
        let successes = u64::from_le_bytes(b[65..73].try_into().unwrap());
        let failures = u64::from_le_bytes(b[73..81].try_into().unwrap());
        let timestamp_secs = u64::from_le_bytes(b[81..89].try_into().unwrap());
        let mut signature = [0u8; ADVERT_SIG_LEN];
        signature.copy_from_slice(&b[89..89 + ADVERT_SIG_LEN]);
        Ok(Self {
            reporter,
            subject,
            successes,
            failures,
            timestamp_secs,
            signature,
        })
    }

    pub fn failure_rate(&self) -> Option<f64> {
        let total = self.successes.saturating_add(self.failures);
        if total == 0 {
            None
        } else {
            Some(self.failures as f64 / total as f64)
        }
    }
}

/// Unix timestamp helper for advert issuance.
pub fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Verify and merge a gossip advert into local peer-health sampling.
///
/// Trust rules (minimal, not BFT):
/// - `link_peer` must equal `advert.reporter` (authenticated hop neighbor).
/// - `reporter` must appear in `peer_table` (admitted neighbor).
/// - Signature must verify under that peer's configured gossip verifying key.
/// - Timestamp must be within `max_age_secs` of `now_secs` (and not far future).
/// - Counts are applied at [`GOSSIP_WEIGHT_NUM`]/[`GOSSIP_WEIGHT_DEN`] weight.
pub fn accept_advert(
    advert: &PeerHealthAdvert,
    link_peer: RelayId,
    peer_table: &HashMap<RelayId, crate::net::PeerInfo>,
    now_secs: u64,
    max_age_secs: u64,
    tracker: &PeerHealthTracker,
) -> Result<(), HealthGossipError> {
    if *link_peer.as_bytes() != advert.reporter {
        return Err(HealthGossipError::ReporterMismatch);
    }
    let peer = peer_table
        .get(&link_peer)
        .ok_or(HealthGossipError::UnknownReporter)?;
    let vk_bytes = peer
        .gossip_verifying_key
        .ok_or(HealthGossipError::MissingVerifyingKey)?;
    let vk =
        VerifyingKey::from_bytes(&vk_bytes).map_err(|_| HealthGossipError::MissingVerifyingKey)?;
    advert.verify(&vk)?;

    let skew_ok = if now_secs >= advert.timestamp_secs {
        now_secs - advert.timestamp_secs <= max_age_secs
    } else {
        // Allow small clock skew into the future (2 minutes).
        advert.timestamp_secs - now_secs <= 120
    };
    if !skew_ok {
        return Err(HealthGossipError::StaleTimestamp);
    }

    tracker.apply_gossip_outcomes(
        advert.subject,
        advert.successes,
        advert.failures,
        GOSSIP_WEIGHT_NUM,
        GOSSIP_WEIGHT_DEN,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::PeerInfo;
    use ed25519_dalek::SigningKey;
    use std::net::SocketAddr;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn id(n: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = n;
        x
    }

    #[test]
    fn sign_verify_cell_roundtrip() {
        let key = sk(7);
        let advert = PeerHealthAdvert::sign(&key, id(1), id(2), 10, 2, 1_700_000_000);
        advert.verify(&key.verifying_key()).unwrap();
        let cell = advert.to_cell();
        assert_eq!(cell.as_bytes()[0], Command::PeerHealthAdvert as u8);
        let parsed = PeerHealthAdvert::from_cell(&cell).unwrap();
        assert_eq!(parsed, advert);
        parsed.verify(&key.verifying_key()).unwrap();
    }

    #[test]
    fn reject_bad_signature() {
        let key = sk(1);
        let mut advert = PeerHealthAdvert::sign(&key, id(1), id(2), 1, 0, 100);
        advert.signature[0] ^= 0xff;
        assert_eq!(
            advert.verify(&key.verifying_key()),
            Err(HealthGossipError::BadSignature)
        );
    }

    #[test]
    fn accept_from_peer_table_neighbor_applies_decay() {
        let key = sk(9);
        let reporter = id(9);
        let subject = id(3);
        let advert = PeerHealthAdvert::sign(&key, reporter, subject, 8, 2, 1_000);
        let mut table = HashMap::new();
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        table.insert(
            RelayId(reporter),
            PeerInfo::new(addr, [0u8; 32])
                .with_gossip_verifying_key(key.verifying_key().to_bytes()),
        );
        let tracker = PeerHealthTracker::new();
        accept_advert(
            &advert,
            RelayId(reporter),
            &table,
            1_000,
            DEFAULT_MAX_ADVERT_AGE_SECS,
            &tracker,
        )
        .unwrap();
        // 8/2 at 1/2 weight → 4 ok, 1 fail → rate 0.2
        let rate = tracker.failure_rate(subject).unwrap();
        assert!((rate - 0.2).abs() < 1e-9);
    }

    #[test]
    fn reject_unknown_reporter() {
        let key = sk(2);
        let advert = PeerHealthAdvert::sign(&key, id(2), id(3), 1, 0, 50);
        let tracker = PeerHealthTracker::new();
        let err = accept_advert(
            &advert,
            RelayId(id(2)),
            &HashMap::new(),
            50,
            DEFAULT_MAX_ADVERT_AGE_SECS,
            &tracker,
        )
        .unwrap_err();
        assert_eq!(err, HealthGossipError::UnknownReporter);
    }

    #[test]
    fn reject_stale_timestamp() {
        let key = sk(4);
        let reporter = id(4);
        let advert = PeerHealthAdvert::sign(&key, reporter, id(5), 1, 0, 10);
        let mut table = HashMap::new();
        let addr: SocketAddr = "127.0.0.1:4".parse().unwrap();
        table.insert(
            RelayId(reporter),
            PeerInfo::new(addr, [0u8; 32])
                .with_gossip_verifying_key(key.verifying_key().to_bytes()),
        );
        let tracker = PeerHealthTracker::new();
        let err = accept_advert(
            &advert,
            RelayId(reporter),
            &table,
            10 + DEFAULT_MAX_ADVERT_AGE_SECS + 1,
            DEFAULT_MAX_ADVERT_AGE_SECS,
            &tracker,
        )
        .unwrap_err();
        assert_eq!(err, HealthGossipError::StaleTimestamp);
    }
}
