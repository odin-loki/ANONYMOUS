//! Permissioned relay admission (spec §4.9).
//!
//! Production admission requires a consortium admission authority signature on each
//! [`RelayRecord`]. Multi-party threshold governance (e.g. M-of-N consortium votes to
//! admit) is future work; this pass uses a single consortium admission-signing key.
//! Signed rosters persist to JSON on disk.

use std::collections::HashMap;
use std::path::Path;

use aegis_trust::reputation::ReputationLedger;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::RosterError;
use crate::types::{RelayId, RelayRecord};

/// Consortium admission authority: signs relay admissions.
#[derive(Clone)]
pub struct ConsortiumKey(SigningKey);

impl ConsortiumKey {
    /// Generate a fresh admission-signing keypair.
    pub fn generate(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        Self(SigningKey::generate(rng))
    }

    /// Wrap an existing signing key (e.g. loaded from secure storage).
    pub fn from_signing_key(key: SigningKey) -> Self {
        Self(key)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// Sign a relay record for admission.
    pub fn sign_record(&self, record: &RelayRecord) -> SignedRelayRecord {
        let signature = self.0.sign(&canonical_record_bytes(record));
        SignedRelayRecord {
            record: record.clone(),
            signature: signature.to_bytes().to_vec(),
            authority_pubkey: self.verifying_key().to_bytes(),
        }
    }
}

/// A relay admission record plus its consortium authority signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRelayRecord {
    pub record: RelayRecord,
    pub signature: Vec<u8>,
    pub authority_pubkey: [u8; 32],
}

impl SignedRelayRecord {
    /// Verify the signature against `authority_pubkey` (must match embedded key).
    pub fn verify(&self, authority_pubkey: &VerifyingKey) -> Result<(), RosterError> {
        if self.authority_pubkey != authority_pubkey.to_bytes() {
            return Err(RosterError::AuthorityMismatch);
        }
        let sig = Signature::from_slice(&self.signature)
            .map_err(|_| RosterError::InvalidSignature { relay: self.record.id })?;
        authority_pubkey
            .verify(&canonical_record_bytes(&self.record), &sig)
            .map_err(|_| RosterError::InvalidSignature {
                relay: self.record.id,
            })
    }
}

/// Canonical byte encoding signed by the consortium admission authority.
fn canonical_record_bytes(record: &RelayRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + record.jurisdiction.0.len());
    bytes.extend_from_slice(&record.id.0);
    bytes.extend_from_slice(record.jurisdiction.0.as_bytes());
    bytes
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RosterEntry {
    record: RelayRecord,
    /// Present when admitted via [`RelayRoster::admit_signed`]; absent for test-only admits.
    signed_admission: Option<SignedRelayRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedRoster {
    version: u32,
    entries: Vec<RosterEntry>,
}

/// In-memory admission list: only rostered relays are eligible for layer assignment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayRoster {
    relays: HashMap<RelayId, RosterEntry>,
}

impl RelayRoster {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a relay without cryptographic authorization.
    ///
    /// **Test-only / no authentication.** Do not use in production deployments;
    /// prefer [`Self::admit_signed`] with a [`ConsortiumKey`] signature.
    pub fn admit(&mut self, relay: RelayRecord) {
        self.relays.insert(
            relay.id,
            RosterEntry {
                record: relay,
                signed_admission: None,
            },
        );
    }

    /// Admit a relay after verifying its consortium authority signature.
    pub fn admit_signed(
        &mut self,
        signed: SignedRelayRecord,
        authority_pubkey: &VerifyingKey,
    ) -> Result<(), RosterError> {
        signed.verify(authority_pubkey)?;
        let id = signed.record.id;
        self.relays.insert(
            id,
            RosterEntry {
                record: signed.record.clone(),
                signed_admission: Some(signed),
            },
        );
        Ok(())
    }

    /// Remove a relay; returns `true` if it was present.
    pub fn remove(&mut self, id: RelayId) -> bool {
        self.relays.remove(&id).is_some()
    }

    pub fn is_admitted(&self, id: RelayId) -> bool {
        self.relays.contains_key(&id)
    }

    pub fn get(&self, id: RelayId) -> Option<&RelayRecord> {
        self.relays.get(&id).map(|e| &e.record)
    }

    pub fn get_signed(&self, id: RelayId) -> Option<&SignedRelayRecord> {
        self.relays
            .get(&id)
            .and_then(|e| e.signed_admission.as_ref())
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// All admitted relays in stable id order (for deterministic epoch assignment).
    pub fn admitted_sorted(&self) -> Vec<RelayRecord> {
        let mut relays: Vec<_> = self.relays.values().map(|e| e.record.clone()).collect();
        relays.sort_by_key(|r| r.id);
        relays
    }

    /// Admitted relays whose [`ReputationLedger`] score is at or above `min_reputation`,
    /// in stable id order (for reputation-filtered topology builds).
    pub fn admitted_sorted_above_reputation(
        &self,
        ledger: &ReputationLedger,
        min_reputation: f64,
    ) -> Vec<RelayRecord> {
        let mut relays: Vec<_> = self
            .relays
            .values()
            .map(|e| e.record.clone())
            .filter(|r| ledger.score(*r.id.as_bytes()).0 >= min_reputation)
            .collect();
        relays.sort_by_key(|r| r.id);
        relays
    }

    /// Persist the roster (including signatures) as human-inspectable JSON.
    pub fn save_to_file(&self, path: &Path) -> std::io::Result<()> {
        let mut entries: Vec<_> = self.relays.values().cloned().collect();
        entries.sort_by_key(|e| e.record.id);
        let persisted = PersistedRoster {
            version: 1,
            entries,
        };
        let json = serde_json::to_string_pretty(&persisted)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load a roster from JSON, re-verifying signed admissions when an authority key is supplied.
    pub fn load_from_file(path: &Path) -> std::io::Result<Self> {
        Self::load_from_file_verified(path, None)
    }

    /// Load from JSON and optionally re-verify every signed admission.
    pub fn load_from_file_verified(
        path: &Path,
        authority_pubkey: Option<&VerifyingKey>,
    ) -> std::io::Result<Self> {
        let bytes = std::fs::read(path)?;
        let persisted: PersistedRoster = serde_json::from_slice(&bytes).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
        let mut roster = RelayRoster::new();
        for entry in persisted.entries {
            if let (Some(signed), Some(pk)) = (&entry.signed_admission, authority_pubkey) {
                signed.verify(pk).map_err(|e| match e {
                    RosterError::Io(err) => err,
                    other => std::io::Error::new(std::io::ErrorKind::InvalidData, other.to_string()),
                })?;
            }
            roster.relays.insert(entry.record.id, entry);
        }
        Ok(roster)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::JurisdictionId;
    use rand::rngs::OsRng;

    fn sample_record(id: u64, jurisdiction: &str) -> RelayRecord {
        RelayRecord {
            id: RelayId::from_u64(id),
            jurisdiction: JurisdictionId::new(jurisdiction),
        }
    }

    #[test]
    fn valid_signed_admission_succeeds() {
        let mut rng = OsRng;
        let authority = ConsortiumKey::generate(&mut rng);
        let pk = authority.verifying_key();
        let record = sample_record(1, "US");
        let signed = authority.sign_record(&record);

        let mut roster = RelayRoster::new();
        roster.admit_signed(signed.clone(), &pk).expect("admit");

        assert!(roster.is_admitted(record.id));
        assert_eq!(roster.get_signed(record.id), Some(&signed));
    }

    #[test]
    fn tampered_record_fails_verification() {
        let mut rng = OsRng;
        let authority = ConsortiumKey::generate(&mut rng);
        let pk = authority.verifying_key();
        let record = sample_record(1, "US");
        let mut signed = authority.sign_record(&record);

        signed.record.jurisdiction = JurisdictionId::new("DE");

        let mut roster = RelayRoster::new();
        let err = roster.admit_signed(signed, &pk).unwrap_err();
        assert!(matches!(err, RosterError::InvalidSignature { .. }));
    }

    #[test]
    fn wrong_authority_key_is_rejected() {
        let mut rng = OsRng;
        let authority = ConsortiumKey::generate(&mut rng);
        let other = ConsortiumKey::generate(&mut rng);
        let record = sample_record(2, "FR");
        let signed = authority.sign_record(&record);

        let mut roster = RelayRoster::new();
        let err = roster
            .admit_signed(signed, &other.verifying_key())
            .unwrap_err();
        assert!(matches!(
            err,
            RosterError::AuthorityMismatch | RosterError::InvalidSignature { .. }
        ));
    }

    #[test]
    fn save_load_round_trip_preserves_signed_admissions() {
        let mut rng = OsRng;
        let authority = ConsortiumKey::generate(&mut rng);
        let pk = authority.verifying_key();

        let mut roster = RelayRoster::new();
        for (id, j) in [(1, "US"), (2, "DE"), (3, "FR")] {
            let signed = authority.sign_record(&sample_record(id, j));
            roster.admit_signed(signed, &pk).expect("admit");
        }

        let dir = std::env::temp_dir().join(format!(
            "aegis-roster-test-{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("roster.json");

        roster.save_to_file(&path).expect("save");
        let loaded =
            RelayRoster::load_from_file_verified(&path, Some(&pk)).expect("load verified");

        assert_eq!(loaded, roster);
        for id in [1, 2, 3] {
            let relay_id = RelayId::from_u64(id);
            let signed = loaded.get_signed(relay_id).expect("signed entry");
            signed.verify(&pk).expect("reloaded signature still valid");
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
