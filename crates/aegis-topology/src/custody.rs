//! Consortium key-ceremony custody boundary (ops workstream #2).
//!
//! [`SoftwareCustodyProvider`] is the lab path: existing Shamir split/reconstruct
//! plus `aegis-ceremony` / [`crate::ceremony::run_ceremony`]. [`HsmCustodyProvider`]
//! is the fail-closed hardware stub (returns [`CeremonyError::HsmUnavailable`] on
//! hosts without an HSM SDK). [`SimulatedHsmProvider`] wraps in-memory software keys
//! behind an HSM-shaped API for **lab/integration tests only** — it is **not**
//! hardware-backed. Use [`select_ceremony_custody`] to pick a mode.
//!
//! See `docs/ops/consortium_key_ceremony.md`.

use std::cell::RefCell;
use std::collections::HashMap;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use crate::roster::{AuthorityAdmissionSignature, ConsortiumKey};
use crate::shamir::{encode_share_hex, split_seed, SeedShare, ShamirError};
use crate::types::RelayRecord;

/// Provider id for software/lab custody (Shamir + file ceremony).
pub const SOFTWARE_CUSTODY_PROVIDER_ID: &str = "software-custody-v1";

/// Provider id for HSM-backed custody (PKCS#11 / vendor SDK).
pub const HSM_CUSTODY_PROVIDER_ID: &str = "hsm-custody-v1";

/// Provider id for lab-only simulated HSM (in-memory keys — **not hardware**).
pub const SIMULATED_HSM_PROVIDER_ID: &str = "simulated-hsm-lab-v1";

/// Required fields for an HSM-wrapped authority seed share export.
///
/// A production PKCS#11 (or vendor) implementation must:
/// 1. Generate an Ed25519 key pair inside the HSM (`C_GenerateKeyPair` or vendor equivalent).
/// 2. Export only a wrapped share blob — never the raw 32-byte seed in cleartext.
/// 3. Bind wrap metadata (authority index, Shamir x-coordinate, custodian id) into the wrap AAD.
///
/// This struct documents the contract; [`HsmCustodyProvider`] does not populate it until a real
/// SDK is wired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsmWrappedShareFields {
    /// HSM key handle or slot label (operator-defined; not secret on its own).
    pub key_label: String,
    /// Opaque wrapped share bytes (vendor wrap / PKCS#11 CKM_AES_KEY_WRAP, etc.).
    pub wrapped_blob: Vec<u8>,
    /// Shamir x-coordinate when the share is part of an M-of-N split (1..=255).
    pub shamir_x: u8,
    /// Ed25519 verifying key for the authority (safe to distribute).
    pub authority_pubkey: [u8; 32],
}

/// PKCS#11 token slot summary for operator inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsmSlotInfo {
    pub slot_id: u64,
    pub label: String,
    pub token_present: bool,
}

/// Custody backend selection for ops / lab wiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeremonyCustodyMode {
    /// Shamir + file ceremony — default for CI and local dev.
    Software,
    /// HSM-held authority keys — fails closed when no PKCS#11 / vendor SDK is present.
    Hardware,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CeremonyError {
    #[error("HSM unavailable: {0}")]
    HsmUnavailable(String),
    #[error("shamir error: {0}")]
    Shamir(#[from] ShamirError),
    #[error("unknown HSM key label: {0}")]
    UnknownKeyLabel(String),
}

/// PKCS#11-shaped custody operations for consortium ceremony (production contract).
///
/// Implementors link a PKCS#11 module (`libsofthsm2`, Luna, YubiHSM, etc.) and map:
/// - [`Pkcs11CustodyOps::list_slots`] → `C_GetSlotList` / token labels
/// - [`Pkcs11CustodyOps::generate_wrap_seed_share`] → in-HSM `C_GenerateKeyPair` + wrap export
/// - [`Pkcs11CustodyOps::sign_admission`] → `C_Sign` without private key export
/// - [`Pkcs11CustodyOps::verify_wrapped_share`] → unwrap metadata + pubkey pin
pub trait Pkcs11CustodyOps {
    fn provider_id(&self) -> &'static str;

    /// Enumerate PKCS#11 slots / tokens (`C_GetSlotList`).
    fn list_slots(&self) -> Result<Vec<HsmSlotInfo>, CeremonyError>;

    /// Generate an authority key in the HSM and export a wrapped Shamir share.
    fn generate_wrap_seed_share(
        &self,
        authority_index: usize,
        shamir_x: u8,
        custodian_label: &str,
    ) -> Result<HsmWrappedShareFields, CeremonyError>;

    /// Sign a relay admission with an HSM-held authority key.
    fn sign_admission(
        &self,
        key_label: &str,
        record: &RelayRecord,
    ) -> Result<AuthorityAdmissionSignature, CeremonyError>;

    /// Verify a wrapped share blob against expected pubkey metadata.
    fn verify_wrapped_share(&self, fields: &HsmWrappedShareFields) -> Result<(), CeremonyError>;
}

/// Actionable operator hint for linking a PKCS#11 / vendor HSM SDK.
pub fn hsm_unavailable_hint() -> &'static str {
    "PKCS#11 HSM unavailable: install vendor module (SoftHSM2, Luna, YubiHSM, etc.), \
     set AEGIS_PKCS11_MODULE path, link cryptoki/pkcs11 crate, and implement \
     HsmCustodyProvider + Pkcs11CustodyOps. See docs/ops/consortium_key_ceremony.md."
}

/// Lab/software custody — Shamir split and in-process signing (existing ceremony path).
pub struct SoftwareCustodyProvider;

impl SoftwareCustodyProvider {
    /// Always available on this build.
    pub fn new() -> Self {
        Self
    }

    pub fn provider_id(&self) -> &'static str {
        SOFTWARE_CUSTODY_PROVIDER_ID
    }

    /// Split a 32-byte authority seed into Shamir shares (GF(256); same as `aegis-ceremony`).
    pub fn split_seed_shares(
        &self,
        seed: &[u8; 32],
        threshold: usize,
        share_count: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Vec<SeedShare>, CeremonyError> {
        split_seed(seed, threshold, share_count, rng).map_err(CeremonyError::from)
    }

    /// Encode a Shamir share as the ceremony hex format (`xx` + 64 hex y bytes).
    pub fn encode_share_hex(&self, share: &SeedShare) -> String {
        encode_share_hex(share)
    }

    /// Sign a relay admission with an in-memory authority key (lab path).
    pub fn sign_admission(
        &self,
        key: &ConsortiumKey,
        record: &RelayRecord,
    ) -> AuthorityAdmissionSignature {
        key.sign_authority(record)
    }

    /// Reconstruct a [`ConsortiumKey`] from a lab-held 32-byte seed.
    pub fn key_from_seed(&self, seed: &[u8; 32]) -> ConsortiumKey {
        let sk = SigningKey::from_bytes(seed);
        ConsortiumKey::from_signing_key(sk)
    }

    /// Verifying key for a lab-held seed (pubkey distribution step).
    pub fn verifying_key_from_seed(&self, seed: &[u8; 32]) -> VerifyingKey {
        self.key_from_seed(seed).verifying_key()
    }
}

impl Default for SoftwareCustodyProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// HSM ceremony custody stub — fail-closed until a PKCS#11 / vendor SDK is linked.
///
/// A production implementation must implement [`Pkcs11CustodyOps`] against real hardware.
/// This workspace has no PKCS#11 dependency; all entry points return
/// [`CeremonyError::HsmUnavailable`] with [`hsm_unavailable_hint`].
pub struct HsmCustodyProvider;

impl HsmCustodyProvider {
    fn unavailable() -> CeremonyError {
        CeremonyError::HsmUnavailable(hsm_unavailable_hint().to_string())
    }

    /// Probe for HSM availability. Always fails on this build.
    pub fn try_new() -> Result<Self, CeremonyError> {
        Self::probe_hardware()
    }

    fn probe_hardware() -> Result<Self, CeremonyError> {
        // Real builds would load PKCS#11 module, probe Thales/Luna/YubiHSM, etc.
        Err(Self::unavailable())
    }
}

impl Pkcs11CustodyOps for HsmCustodyProvider {
    fn provider_id(&self) -> &'static str {
        HSM_CUSTODY_PROVIDER_ID
    }

    fn list_slots(&self) -> Result<Vec<HsmSlotInfo>, CeremonyError> {
        Err(Self::unavailable())
    }

    fn generate_wrap_seed_share(
        &self,
        _authority_index: usize,
        _shamir_x: u8,
        _custodian_label: &str,
    ) -> Result<HsmWrappedShareFields, CeremonyError> {
        Err(Self::unavailable())
    }

    fn sign_admission(
        &self,
        _key_label: &str,
        _record: &RelayRecord,
    ) -> Result<AuthorityAdmissionSignature, CeremonyError> {
        Err(Self::unavailable())
    }

    fn verify_wrapped_share(&self, _fields: &HsmWrappedShareFields) -> Result<(), CeremonyError> {
        Err(Self::unavailable())
    }
}

/// Lab-only simulated HSM — software keys behind PKCS#11-shaped API.
///
/// **NOT hardware-backed.** Use only in CI/integration tests to exercise
/// HSM-shaped call sites. Never deploy in production or claim HSM custody.
pub struct SimulatedHsmProvider {
    software: SoftwareCustodyProvider,
    keys: RefCell<HashMap<String, ConsortiumKey>>,
    next_slot: RefCell<u64>,
}

impl SimulatedHsmProvider {
    pub fn new_lab_only() -> Self {
        Self {
            software: SoftwareCustodyProvider::new(),
            keys: RefCell::new(HashMap::new()),
            next_slot: RefCell::new(1),
        }
    }

    fn wrap_blob(label: &str, shamir_x: u8, pubkey: &[u8; 32]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(label.len() + 33);
        blob.extend_from_slice(b"SIMHSM-LAB-v1:");
        blob.extend_from_slice(label.as_bytes());
        blob.push(shamir_x);
        blob.extend_from_slice(pubkey);
        blob
    }
}

impl Pkcs11CustodyOps for SimulatedHsmProvider {
    fn provider_id(&self) -> &'static str {
        SIMULATED_HSM_PROVIDER_ID
    }

    fn list_slots(&self) -> Result<Vec<HsmSlotInfo>, CeremonyError> {
        let keys = self.keys.borrow();
        let mut slots: Vec<_> = keys
            .keys()
            .enumerate()
            .map(|(i, label)| HsmSlotInfo {
                slot_id: i as u64 + 1,
                label: label.clone(),
                token_present: true,
            })
            .collect();
        slots.sort_by_key(|s| s.slot_id);
        if slots.is_empty() {
            slots.push(HsmSlotInfo {
                slot_id: 0,
                label: "sim-empty".to_string(),
                token_present: false,
            });
        }
        Ok(slots)
    }

    fn generate_wrap_seed_share(
        &self,
        authority_index: usize,
        shamir_x: u8,
        custodian_label: &str,
    ) -> Result<HsmWrappedShareFields, CeremonyError> {
        let label = format!("sim-slot-{authority_index}-{custodian_label}");
        let key = ConsortiumKey::generate(&mut rand::rngs::OsRng);
        let pubkey = *key.verifying_key().as_bytes();
        self.keys.borrow_mut().insert(label.clone(), key);
        let next = self.next_slot.borrow().saturating_add(1);
        *self.next_slot.borrow_mut() = next;
        Ok(HsmWrappedShareFields {
            key_label: label,
            wrapped_blob: Self::wrap_blob(&format!("{authority_index}"), shamir_x, &pubkey),
            shamir_x,
            authority_pubkey: pubkey,
        })
    }

    fn sign_admission(
        &self,
        key_label: &str,
        record: &RelayRecord,
    ) -> Result<AuthorityAdmissionSignature, CeremonyError> {
        let keys = self.keys.borrow();
        let key = keys
            .get(key_label)
            .ok_or_else(|| CeremonyError::UnknownKeyLabel(key_label.to_string()))?;
        Ok(self.software.sign_admission(key, record))
    }

    fn verify_wrapped_share(&self, fields: &HsmWrappedShareFields) -> Result<(), CeremonyError> {
        let keys = self.keys.borrow();
        let key = keys
            .get(&fields.key_label)
            .ok_or_else(|| CeremonyError::UnknownKeyLabel(fields.key_label.clone()))?;
        if *key.verifying_key().as_bytes() != fields.authority_pubkey {
            return Err(CeremonyError::UnknownKeyLabel(fields.key_label.clone()));
        }
        Ok(())
    }
}

/// Select a ceremony custody backend by mode.
///
/// - [`CeremonyCustodyMode::Software`] — returns [`SoftwareCustodyProvider`] (Shamir + file ceremony).
/// - [`CeremonyCustodyMode::Hardware`] — fails closed with [`CeremonyError::HsmUnavailable`]
///   when no HSM SDK is present (always on this workspace build).
pub fn select_ceremony_custody(
    mode: CeremonyCustodyMode,
) -> Result<SoftwareCustodyProvider, CeremonyError> {
    match mode {
        CeremonyCustodyMode::Software => Ok(SoftwareCustodyProvider::new()),
        CeremonyCustodyMode::Hardware => {
            HsmCustodyProvider::try_new()?;
            unreachable!("HSM probe succeeded but no provider wired")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    use crate::ceremony::{run_ceremony, CeremonyConfig};
    use crate::roster::{ThresholdConsortium, ThresholdSignedRelayRecord};
    use crate::types::JurisdictionId;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "aegis-custody-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn select_ceremony_custody_software_path() {
        let provider = select_ceremony_custody(CeremonyCustodyMode::Software).expect("software");
        assert_eq!(provider.provider_id(), SOFTWARE_CUSTODY_PROVIDER_ID);

        let seed = [0x11u8; 32];
        let shares = provider
            .split_seed_shares(&seed, 2, 3, &mut OsRng)
            .expect("shamir split");
        assert_eq!(shares.len(), 3);
        assert!(!provider.encode_share_hex(&shares[0]).is_empty());
    }

    #[test]
    fn software_custody_signs_admission() {
        let provider = SoftwareCustodyProvider::new();
        let key = ConsortiumKey::generate(&mut OsRng);
        let (_kem_sec, kem_pk) = aegis_crypto::kem::RelayKemSecret::generate(&mut OsRng);
        let record =
            RelayRecord::from_kem_public(JurisdictionId::new("US"), &kem_pk);
        let sig = provider.sign_admission(&key, &record);
        let signed = ThresholdSignedRelayRecord::new(record.clone())
            .with_signature(sig);
        let consortium = ThresholdConsortium::single(key.verifying_key());
        signed.verify_threshold(&consortium).expect("verify admission");
    }

    #[test]
    fn software_custody_run_ceremony_still_works() {
        let dir = temp_dir("ceremony");
        let _ = std::fs::remove_dir_all(&dir);

        let _provider = select_ceremony_custody(CeremonyCustodyMode::Software).expect("software");
        let cfg = CeremonyConfig {
            n: 2,
            threshold: 2,
            jurisdiction: "DE".into(),
            write_seeds: true,
            shamir_n: Some(3),
            shamir_threshold: Some(2),
        };
        let out = run_ceremony(&dir, &cfg, &mut OsRng).expect("ceremony");
        assert_eq!(out.authority_pubkeys_hex.len(), 2);
        out.sample_admission
            .verify_threshold(&out.consortium)
            .expect("verify");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hsm_provider_fails_closed_on_this_host() {
        assert!(matches!(
            HsmCustodyProvider::try_new(),
            Err(CeremonyError::HsmUnavailable(_))
        ));
    }

    #[test]
    fn hsm_pkcs11_ops_fail_closed_with_hint() {
        let provider = HsmCustodyProvider;
        assert!(matches!(
            Pkcs11CustodyOps::list_slots(&provider),
            Err(CeremonyError::HsmUnavailable(ref m)) if m.contains("PKCS#11")
        ));
        assert!(matches!(
            provider.generate_wrap_seed_share(0, 1, "custodian-a"),
            Err(CeremonyError::HsmUnavailable(_))
        ));
    }

    #[test]
    fn hsm_sign_admission_fails_closed() {
        let (_kem_sec, kem_pk) = aegis_crypto::kem::RelayKemSecret::generate(&mut OsRng);
        let record =
            RelayRecord::from_kem_public(JurisdictionId::new("US"), &kem_pk);
        assert!(matches!(
            Pkcs11CustodyOps::sign_admission(&HsmCustodyProvider, "authority-0", &record),
            Err(CeremonyError::HsmUnavailable(_))
        ));
    }

    #[test]
    fn select_ceremony_custody_hardware_fails_closed() {
        assert!(matches!(
            select_ceremony_custody(CeremonyCustodyMode::Hardware),
            Err(CeremonyError::HsmUnavailable(_))
        ));
    }

    #[test]
    fn simulated_hsm_lab_only_roundtrip() {
        let sim = SimulatedHsmProvider::new_lab_only();
        assert_eq!(sim.provider_id(), SIMULATED_HSM_PROVIDER_ID);

        let wrapped = sim
            .generate_wrap_seed_share(0, 1, "custodian-a")
            .expect("sim wrap");
        sim.verify_wrapped_share(&wrapped).expect("verify wrap");

        let (_kem_sec, kem_pk) = aegis_crypto::kem::RelayKemSecret::generate(&mut OsRng);
        let record =
            RelayRecord::from_kem_public(JurisdictionId::new("US"), &kem_pk);
        let sig = sim
            .sign_admission(&wrapped.key_label, &record)
            .expect("sim sign");
        let signed = ThresholdSignedRelayRecord::new(record.clone()).with_signature(sig);
        let consortium = ThresholdConsortium::single(
            VerifyingKey::from_bytes(&wrapped.authority_pubkey).expect("pk"),
        );
        signed.verify_threshold(&consortium).expect("verify");

        let slots = sim.list_slots().expect("slots");
        assert!(slots.iter().any(|s| s.token_present));
    }
}
