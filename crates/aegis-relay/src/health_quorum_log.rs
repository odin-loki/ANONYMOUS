//! BFT-lite append-only quorum log for signed [`PeerHealthAdvert`] observations.
//!
//! **Not** multi-org BFT consensus: a local, persisted log that buffers verified
//! adverts per `(epoch, subject)` until `majority_k` distinct **authority** reporters
//! agree, then applies the median merge into [`PeerHealthTracker`]. Rejects
//! equivocation (conflicting payloads for the same `epoch + reporter + subject`).

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use thiserror::Error;

use crate::health_gossip::PeerHealthAdvert;
use crate::peer_health::{PeerHealthTracker, GOSSIP_WEIGHT_DEN, GOSSIP_WEIGHT_NUM};

/// On-disk record size: epoch + reporter + subject + successes + failures + signature.
pub const QUORUM_LOG_RECORD_LEN: usize = 8 + 32 + 32 + 8 + 8 + 64;

const EPOCH_CHECKPOINT_DOMAIN: &[u8] = b"aegis-health-epoch-checkpoint-v1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum QuorumLogError {
    #[error("malformed quorum log record")]
    Malformed,
    #[error("invalid gossip signature")]
    BadSignature,
    #[error("reporter is not in the authority set")]
    NotAuthority,
    #[error("equivocation: conflicting advert for same epoch and reporter")]
    Equivocation,
    #[error("io error: {0}")]
    Io(String),
}

/// One persisted, signed gossip observation scoped to a gossip epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthQuorumLogEntry {
    pub epoch: u64,
    pub advert: PeerHealthAdvert,
}

impl HealthQuorumLogEntry {
    /// Canonical on-disk bytes (includes epoch prefix before advert body).
    pub fn record_bytes(&self) -> [u8; QUORUM_LOG_RECORD_LEN] {
        let mut out = [0u8; QUORUM_LOG_RECORD_LEN];
        out[0..8].copy_from_slice(&self.epoch.to_le_bytes());
        out[8..8 + 32].copy_from_slice(&self.advert.reporter);
        out[40..72].copy_from_slice(&self.advert.subject);
        out[72..80].copy_from_slice(&self.advert.successes.to_le_bytes());
        out[80..88].copy_from_slice(&self.advert.failures.to_le_bytes());
        out[88..152].copy_from_slice(&self.advert.signature);
        out
    }

    pub fn from_record_bytes(buf: &[u8]) -> Result<Self, QuorumLogError> {
        if buf.len() != QUORUM_LOG_RECORD_LEN {
            return Err(QuorumLogError::Malformed);
        }
        let epoch = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let mut reporter = [0u8; 32];
        let mut subject = [0u8; 32];
        reporter.copy_from_slice(&buf[8..40]);
        subject.copy_from_slice(&buf[40..72]);
        let successes = u64::from_le_bytes(buf[72..80].try_into().unwrap());
        let failures = u64::from_le_bytes(buf[80..88].try_into().unwrap());
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[88..152]);
        Ok(Self {
            epoch,
            advert: PeerHealthAdvert {
                reporter,
                subject,
                successes,
                failures,
                timestamp_secs: 0,
                signature,
            },
        })
    }

    pub fn payload_key(&self) -> ([u8; 32], [u8; 32], u64, u64) {
        (
            self.advert.reporter,
            self.advert.subject,
            self.advert.successes,
            self.advert.failures,
        )
    }
}

/// One quorum-accepted median observation for a subject within a gossip epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthEpochMedianSummary {
    pub subject: [u8; 32],
    pub successes: u64,
    pub failures: u64,
}

/// Signed rollup of all quorum-accepted medians for one gossip epoch.
///
/// Optional operator artifact — **not** multi-org BFT consensus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthEpochCheckpoint {
    pub epoch: u64,
    pub summaries: Vec<HealthEpochMedianSummary>,
    pub signer_pubkey: [u8; 32],
    pub signature: Vec<u8>,
}

impl HealthEpochCheckpoint {
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), QuorumLogError> {
        let msg = canonical_checkpoint_bytes(self.epoch, &self.summaries);
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| QuorumLogError::BadSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key
            .verify(&msg, &sig)
            .map_err(|_| QuorumLogError::BadSignature)
    }
}

/// Result of appending a verified advert to the quorum log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuorumAppendOutcome {
    /// Appended; waiting for more distinct authority reporters.
    Buffered { have: usize, need: usize },
    /// Quorum reached; median merge applied to the tracker.
    Applied { reporters: usize },
    /// Duplicate identical re-append (idempotent).
    Duplicate,
}

/// Append-only signed log with epoch-scoped quorum merge.
#[derive(Clone, Debug)]
pub struct HealthQuorumLog {
    path: Option<PathBuf>,
    majority_k: usize,
    authority_set: HashSet<[u8; 32]>,
    /// `(epoch, reporter, subject)` → canonical payload fingerprint.
    seen: HashMap<(u64, [u8; 32], [u8; 32]), (u64, u64)>,
    /// `(epoch, subject)` → reporter → (successes, failures).
    pending: HashMap<(u64, [u8; 32]), HashMap<[u8; 32], (u64, u64)>>,
    applied: HashSet<(u64, [u8; 32])>,
    /// Quorum-accepted median `(successes, failures)` per `(epoch, subject)`.
    applied_medians: HashMap<(u64, [u8; 32]), (u64, u64)>,
    entries: Vec<HealthQuorumLogEntry>,
}

impl HealthQuorumLog {
    pub fn new(majority_k: usize, authority_set: HashSet<[u8; 32]>) -> Self {
        Self {
            path: None,
            majority_k: majority_k.max(1),
            authority_set,
            seen: HashMap::new(),
            pending: HashMap::new(),
            applied: HashSet::new(),
            applied_medians: HashMap::new(),
            entries: Vec::new(),
        }
    }

    pub fn with_persist_path(mut self, path: impl AsRef<Path>) -> Self {
        self.path = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn majority_k(&self) -> usize {
        self.majority_k
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn epoch_subject_applied(&self, epoch: u64, subject: [u8; 32]) -> bool {
        self.applied.contains(&(epoch, subject))
    }

    /// Accepted median summaries for `epoch`, sorted by subject id.
    pub fn applied_summaries_for_epoch(&self, epoch: u64) -> Vec<HealthEpochMedianSummary> {
        let mut out: Vec<HealthEpochMedianSummary> = self
            .applied_medians
            .iter()
            .filter(|((e, _), _)| *e == epoch)
            .map(|((_, subject), (ok, fail))| HealthEpochMedianSummary {
                subject: *subject,
                successes: *ok,
                failures: *fail,
            })
            .collect();
        out.sort_by_key(|s| s.subject);
        out
    }

    /// Sign a checkpoint over all quorum-accepted medians for `epoch`.
    pub fn sign_epoch_checkpoint(
        &self,
        epoch: u64,
        signing_key: &SigningKey,
    ) -> HealthEpochCheckpoint {
        let summaries = self.applied_summaries_for_epoch(epoch);
        let msg = canonical_checkpoint_bytes(epoch, &summaries);
        let signature = signing_key.sign(&msg).to_bytes().to_vec();
        HealthEpochCheckpoint {
            epoch,
            summaries,
            signer_pubkey: signing_key.verifying_key().to_bytes(),
            signature,
        }
    }

    /// Load an existing log from `path`, or create an empty one if missing.
    pub fn load_or_create(
        path: impl AsRef<Path>,
        majority_k: usize,
        authority_set: HashSet<[u8; 32]>,
    ) -> Result<Self, QuorumLogError> {
        let path = path.as_ref().to_path_buf();
        let mut log = Self::new(majority_k, authority_set).with_persist_path(&path);
        if path.exists() {
            log.replay_from_disk()?;
        }
        Ok(log)
    }

    fn replay_from_disk(&mut self) -> Result<(), QuorumLogError> {
        let file = File::open(self.path.as_ref().unwrap())
            .map_err(|e| QuorumLogError::Io(e.to_string()))?;
        let mut reader = BufReader::new(file);
        let mut buf = [0u8; QUORUM_LOG_RECORD_LEN];
        while reader.read_exact(&mut buf).is_ok() {
            let entry = HealthQuorumLogEntry::from_record_bytes(&buf)?;
            self.replay_entry(entry)?;
        }
        self.finalize_replayed_quorums();
        Ok(())
    }

    fn finalize_replayed_quorums(&mut self) {
        let ready: Vec<(u64, [u8; 32])> = self
            .pending
            .iter()
            .filter(|(_, reporters)| reporters.len() >= self.majority_k)
            .map(|(key, _)| *key)
            .collect();
        for (epoch, subject) in ready {
            if let Some(by_reporter) = self.pending.get(&(epoch, subject)) {
                let observations: Vec<(u64, u64)> = by_reporter.values().copied().collect();
                if let Some((ok, fail)) = crate::peer_health::median_outcome_counts(&observations)
                {
                    self.applied_medians.insert((epoch, subject), (ok, fail));
                }
            }
            self.applied.insert((epoch, subject));
            self.pending.remove(&(epoch, subject));
        }
    }

    fn replay_entry(&mut self, entry: HealthQuorumLogEntry) -> Result<(), QuorumLogError> {
        let key = (
            entry.epoch,
            entry.advert.reporter,
            entry.advert.subject,
        );
        let payload = (entry.advert.successes, entry.advert.failures);
        if let Some(prev) = self.seen.get(&key) {
            if *prev != payload {
                return Err(QuorumLogError::Equivocation);
            }
        } else {
            self.seen.insert(key, payload);
        }
        self.entries.push(entry.clone());
        if self.applied.contains(&(entry.epoch, entry.advert.subject)) {
            return Ok(());
        }
        if !self.authority_set.is_empty() && !self.authority_set.contains(&entry.advert.reporter) {
            return Ok(());
        }
        let pending_key = (entry.epoch, entry.advert.subject);
        self.pending
            .entry(pending_key)
            .or_default()
            .insert(entry.advert.reporter, payload);
        Ok(())
    }

    fn persist_entry(&self, entry: &HealthQuorumLogEntry) -> Result<(), QuorumLogError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| QuorumLogError::Io(e.to_string()))?;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| QuorumLogError::Io(e.to_string()))?;
        file.write_all(&entry.record_bytes())
            .map_err(|e| QuorumLogError::Io(e.to_string()))?;
        file.flush().map_err(|e| QuorumLogError::Io(e.to_string()))?;
        Ok(())
    }

    /// Verify signature, enforce authority set, append, detect equivocation, try quorum merge.
    pub fn append_verified(
        &mut self,
        epoch: u64,
        advert: &PeerHealthAdvert,
        verifying_key: &VerifyingKey,
        tracker: &PeerHealthTracker,
    ) -> Result<QuorumAppendOutcome, QuorumLogError> {
        advert
            .verify(verifying_key)
            .map_err(|_| QuorumLogError::BadSignature)?;

        if !self.authority_set.is_empty() && !self.authority_set.contains(&advert.reporter) {
            return Err(QuorumLogError::NotAuthority);
        }

        let dedup_key = (epoch, advert.reporter, advert.subject);
        let payload = (advert.successes, advert.failures);
        if let Some(prev) = self.seen.get(&dedup_key) {
            if *prev != payload {
                return Err(QuorumLogError::Equivocation);
            }
            return Ok(QuorumAppendOutcome::Duplicate);
        }
        self.seen.insert(dedup_key, payload);

        let entry = HealthQuorumLogEntry {
            epoch,
            advert: advert.clone(),
        };
        self.entries.push(entry.clone());
        self.persist_entry(&entry)?;

        if self.applied.contains(&(epoch, advert.subject)) {
            return Ok(QuorumAppendOutcome::Duplicate);
        }

        let pending_key = (epoch, advert.subject);
        let by_reporter = self.pending.entry(pending_key).or_default();
        by_reporter.insert(advert.reporter, payload);
        let have = by_reporter.len();
        let k = self.majority_k;
        if have < k {
            return Ok(QuorumAppendOutcome::Buffered { have, need: k });
        }

        let observations: Vec<(u64, u64)> = by_reporter.values().copied().collect();
        by_reporter.clear();
        self.applied.insert((epoch, advert.subject));

        if let Some((ok, fail)) = crate::peer_health::median_outcome_counts(&observations) {
            self.applied_medians
                .insert((epoch, advert.subject), (ok, fail));
            tracker.apply_gossip_outcomes(
                advert.subject,
                ok,
                fail,
                GOSSIP_WEIGHT_NUM,
                GOSSIP_WEIGHT_DEN,
            );
        }
        Ok(QuorumAppendOutcome::Applied { reporters: have })
    }
}

fn canonical_checkpoint_bytes(epoch: u64, summaries: &[HealthEpochMedianSummary]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(EPOCH_CHECKPOINT_DOMAIN.len() + 8 + summaries.len() * 48);
    msg.extend_from_slice(EPOCH_CHECKPOINT_DOMAIN);
    msg.extend_from_slice(&epoch.to_le_bytes());
    for summary in summaries {
        msg.extend_from_slice(&summary.subject);
        msg.extend_from_slice(&summary.successes.to_le_bytes());
        msg.extend_from_slice(&summary.failures.to_le_bytes());
    }
    msg
}

/// Map advert timestamp into a gossip epoch bucket.
pub fn advert_epoch(timestamp_secs: u64, epoch_secs: u64) -> u64 {
    let bucket = epoch_secs.max(1);
    timestamp_secs / bucket
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health_gossip::PeerHealthAdvert;
    use ed25519_dalek::SigningKey;

    fn sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn id(n: u8) -> [u8; 32] {
        let mut x = [0u8; 32];
        x[0] = n;
        x
    }

    fn authorities(reporters: &[u8]) -> HashSet<[u8; 32]> {
        reporters.iter().map(|n| id(*n)).collect()
    }

    #[test]
    fn honest_quorum_accepts_and_applies_median() {
        let subject = id(50);
        let epoch = 100;
        let tracker = PeerHealthTracker::with_gossip_majority_k(3);
        let mut log = HealthQuorumLog::new(2, authorities(&[1, 2, 3]));

        let a1 = PeerHealthAdvert::sign(&sk(1), id(1), subject, 90, 10, 1_000);
        let a2 = PeerHealthAdvert::sign(&sk(2), id(2), subject, 88, 12, 1_000);
        let a3 = PeerHealthAdvert::sign(&sk(3), id(3), subject, 92, 8, 1_000);

        let out1 = log
            .append_verified(epoch, &a1, &sk(1).verifying_key(), &tracker)
            .unwrap();
        assert_eq!(out1, QuorumAppendOutcome::Buffered { have: 1, need: 2 });

        let out2 = log
            .append_verified(epoch, &a2, &sk(2).verifying_key(), &tracker)
            .unwrap();
        assert_eq!(out2, QuorumAppendOutcome::Applied { reporters: 2 });

        let rate = tracker.failure_rate(subject).unwrap();
        assert!(rate > 0.05 && rate < 0.15, "median ~10% expected, got {rate}");

        // Third reporter after quorum is duplicate epoch apply path
        let out3 = log
            .append_verified(epoch, &a3, &sk(3).verifying_key(), &tracker)
            .unwrap();
        assert_eq!(out3, QuorumAppendOutcome::Duplicate);
    }

    #[test]
    fn single_byzantine_advert_buffered_not_applied() {
        let subject = id(7);
        let epoch = 5;
        let tracker = PeerHealthTracker::with_gossip_majority_k(2);
        let mut log = HealthQuorumLog::new(2, authorities(&[9, 10]));

        let evil = PeerHealthAdvert::sign(&sk(9), id(9), subject, 0, 100, 500);
        let out = log
            .append_verified(epoch, &evil, &sk(9).verifying_key(), &tracker)
            .unwrap();
        assert_eq!(out, QuorumAppendOutcome::Buffered { have: 1, need: 2 });
        assert!(tracker.failure_rate(subject).is_none());
    }

    #[test]
    fn equivocation_rejected() {
        let subject = id(3);
        let epoch = 1;
        let tracker = PeerHealthTracker::new();
        let mut log = HealthQuorumLog::new(1, authorities(&[4]));

        let a1 = PeerHealthAdvert::sign(&sk(4), id(4), subject, 10, 0, 100);
        log.append_verified(epoch, &a1, &sk(4).verifying_key(), &tracker)
            .unwrap();

        let a2 = PeerHealthAdvert::sign(&sk(4), id(4), subject, 0, 10, 100);
        let err = log
            .append_verified(epoch, &a2, &sk(4).verifying_key(), &tracker)
            .unwrap_err();
        assert_eq!(err, QuorumLogError::Equivocation);
    }

    #[test]
    fn persist_and_reload_replays_state() {
        let dir = std::env::temp_dir().join(format!("aegis_quorum_log_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("health_quorum.log");

        let subject = id(8);
        let epoch = 42;
        {
            let tracker = PeerHealthTracker::new();
            let mut log =
                HealthQuorumLog::load_or_create(&path, 2, authorities(&[1, 2])).unwrap();
            let a1 = PeerHealthAdvert::sign(&sk(1), id(1), subject, 9, 1, 200);
            let a2 = PeerHealthAdvert::sign(&sk(2), id(2), subject, 8, 2, 200);
            log.append_verified(epoch, &a1, &sk(1).verifying_key(), &tracker)
                .unwrap();
            log.append_verified(epoch, &a2, &sk(2).verifying_key(), &tracker)
                .unwrap();
            assert_eq!(log.entry_count(), 2);
        }

        let reloaded = HealthQuorumLog::load_or_create(&path, 2, authorities(&[1, 2])).unwrap();
        assert_eq!(reloaded.entry_count(), 2);
        assert!(reloaded.epoch_subject_applied(epoch, subject));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_authority_reporter_rejected() {
        let subject = id(11);
        let epoch = 2;
        let tracker = PeerHealthTracker::new();
        let mut log = HealthQuorumLog::new(1, authorities(&[1]));

        let advert = PeerHealthAdvert::sign(&sk(99), id(99), subject, 5, 5, 100);
        let err = log
            .append_verified(epoch, &advert, &sk(99).verifying_key(), &tracker)
            .unwrap_err();
        assert_eq!(err, QuorumLogError::NotAuthority);
    }

    #[test]
    fn epoch_checkpoint_signs_accepted_medians() {
        let subject = id(20);
        let epoch = 9;
        let tracker = PeerHealthTracker::new();
        let mut log = HealthQuorumLog::new(2, authorities(&[1, 2]));
        let ck_key = sk(77);

        let a1 = PeerHealthAdvert::sign(&sk(1), id(1), subject, 90, 10, 500);
        let a2 = PeerHealthAdvert::sign(&sk(2), id(2), subject, 88, 12, 500);
        log.append_verified(epoch, &a1, &sk(1).verifying_key(), &tracker)
            .unwrap();
        log.append_verified(epoch, &a2, &sk(2).verifying_key(), &tracker)
            .unwrap();

        let checkpoint = log.sign_epoch_checkpoint(epoch, &ck_key);
        assert_eq!(checkpoint.summaries.len(), 1);
        assert_eq!(checkpoint.summaries[0].subject, subject);
        checkpoint
            .verify(&ck_key.verifying_key())
            .expect("checkpoint signature must verify");

        let mut tampered = checkpoint.clone();
        tampered.summaries[0].failures += 1;
        assert!(tampered.verify(&ck_key.verifying_key()).is_err());
    }

    #[test]
    fn record_roundtrip() {
        let advert = PeerHealthAdvert::sign(&sk(1), id(1), id(2), 3, 1, 999);
        let entry = HealthQuorumLogEntry {
            epoch: 7,
            advert,
        };
        let bytes = entry.record_bytes();
        let parsed = HealthQuorumLogEntry::from_record_bytes(&bytes).unwrap();
        assert_eq!(parsed.epoch, 7);
        assert_eq!(parsed.advert.reporter, entry.advert.reporter);
        assert_eq!(parsed.advert.successes, entry.advert.successes);
        assert_eq!(parsed.advert.signature, entry.advert.signature);
    }
}
