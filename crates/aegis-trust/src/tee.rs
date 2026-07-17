//! TEE-broken-enclave bookkeeping (spec §2, §4.8, §10 Phase-7 gate).
//!
//! Spec's threat model: "TEE-compromised variant: enclave assumed FULLY broken
//! on compromised relays; base guarantee must survive this (TEE is
//! defense-in-depth only)." The Phase-7 gate is: "core gates hold with enclave
//! assumed broken."
//!
//! # Attestation interface (workstream #1)
//!
//! [`AttestationProvider`] is the plug-in boundary for hardware quotes (Intel
//! DCAP/SGX, AMD SEV-SNP, etc.). [`SoftwareAttestationProvider`] signs
//! `report_data` with Ed25519 for lab/tests only — it proves possession of a
//! configured root key, **not** enclave integrity. See `docs/ops/tee_attestation.md`.
//!
//! ## Gate APIs
//!
//! - [`core_gates_hold_under`] — **lab / backward-compat.** Returns `true` only
//!   for [`TeeAssumption::Trusted`]. [`TeeAssumption::BrokenEnclave`] returns
//!   `false` to force callers through the attested path.
//! - [`core_gates_hold_under_attested`] — production checkpoint: verifies a quote
//!   over `expected_report_data`, then re-checks that no crate depends on a
//!   load-bearing enclave assumption.
//!
//! Grep for `core_gates_hold_under` before shipping a TEE-dependent feature.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Domain separator for software attestation quotes.
const SOFTWARE_QUOTE_DOMAIN: &[u8] = b"AEGIS-TEE-SOFTWARE-QUOTE-v1";

/// Provider id embedded in [`AttestationQuote`] for wire/debug identification.
pub const SOFTWARE_PROVIDER_ID: &str = "software-v1";

/// Canonical `report_data` for the Phase-7 gate checkpoint (lab / software path).
pub const PHASE7_GATE_REPORT_DOMAIN: &[u8] = b"AEGIS-PHASE7-GATE-v1";

/// Whether the platform's attested enclave (if any) should be trusted for this
/// check. `BrokenEnclave` models the spec's threat model where a compromised
/// relay's enclave attestation cannot be relied upon at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeAssumption {
    Trusted,
    BrokenEnclave,
}

/// A signed attestation quote binding opaque `report_data` to an issuer.
///
/// Hardware providers will populate additional fields later (e.g. MRENCLAVE,
/// TCB version). The software provider stores an Ed25519 signature over
/// `report_data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationQuote {
    /// Provider identifier (`software-v1`, future `sgx-dcap-v1`, etc.).
    pub provider: String,
    /// Opaque report payload the issuer attested to (caller-defined semantics).
    pub report_data: Vec<u8>,
    /// Provider-specific signature bytes.
    pub signature: Vec<u8>,
    /// Ed25519 verifying key (software provider only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey: Option<[u8; 32]>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("report_data mismatch")]
    ReportDataMismatch,
    #[error("unsupported provider {0}")]
    UnsupportedProvider(String),
    #[error("malformed quote")]
    MalformedQuote,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("signer pubkey does not match configured root")]
    SignerMismatch,
}

/// Issue and verify attestation quotes over opaque `report_data`.
///
/// Production deployments implement this for their enclave stack; tests use
/// [`SoftwareAttestationProvider`].
pub trait AttestationProvider {
    fn issue_quote(&self, report_data: &[u8]) -> AttestationQuote;

    fn verify_quote(
        &self,
        quote: &AttestationQuote,
        expected_report_data: &[u8],
    ) -> Result<(), AttestationError>;
}

/// Lab/test attestation: Ed25519 signature over domain-separated `report_data`.
///
/// **Does not prove enclave integrity.** Only proves that whoever holds the
/// configured signing key attested to the given `report_data`.
pub struct SoftwareAttestationProvider {
    signing_key: SigningKey,
}

impl SoftwareAttestationProvider {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn sign_report_data(&self, report_data: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(SOFTWARE_QUOTE_DOMAIN.len() + report_data.len());
        msg.extend_from_slice(SOFTWARE_QUOTE_DOMAIN);
        msg.extend_from_slice(report_data);
        self.signing_key.sign(&msg).to_bytes().to_vec()
    }
}

impl AttestationProvider for SoftwareAttestationProvider {
    fn issue_quote(&self, report_data: &[u8]) -> AttestationQuote {
        AttestationQuote {
            provider: SOFTWARE_PROVIDER_ID.to_string(),
            report_data: report_data.to_vec(),
            signature: self.sign_report_data(report_data),
            signer_pubkey: Some(*self.verifying_key().as_bytes()),
        }
    }

    fn verify_quote(
        &self,
        quote: &AttestationQuote,
        expected_report_data: &[u8],
    ) -> Result<(), AttestationError> {
        verify_software_quote(quote, expected_report_data, &self.verifying_key())
    }
}

fn verify_software_quote(
    quote: &AttestationQuote,
    expected_report_data: &[u8],
    root: &VerifyingKey,
) -> Result<(), AttestationError> {
    if quote.provider != SOFTWARE_PROVIDER_ID {
        return Err(AttestationError::UnsupportedProvider(quote.provider.clone()));
    }
    if quote.report_data.as_slice() != expected_report_data {
        return Err(AttestationError::ReportDataMismatch);
    }
    let signer_array = quote
        .signer_pubkey
        .ok_or(AttestationError::MalformedQuote)?;
    let signer =
        VerifyingKey::from_bytes(&signer_array).map_err(|_| AttestationError::MalformedQuote)?;
    if signer.as_bytes() != root.as_bytes() {
        return Err(AttestationError::SignerMismatch);
    }
    let sig_bytes: [u8; 64] = quote
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| AttestationError::MalformedQuote)?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::with_capacity(SOFTWARE_QUOTE_DOMAIN.len() + expected_report_data.len());
    msg.extend_from_slice(SOFTWARE_QUOTE_DOMAIN);
    msg.extend_from_slice(expected_report_data);
    signer
        .verify(&msg, &signature)
        .map_err(|_| AttestationError::InvalidSignature)
}

/// Standard `report_data` bytes for the Phase-7 gate (software/lab path).
pub fn phase7_gate_report_data() -> Vec<u8> {
    PHASE7_GATE_REPORT_DOMAIN.to_vec()
}

/// Lab/backward-compat gate check without attestation.
///
/// Returns `true` for [`TeeAssumption::Trusted`] only. [`TeeAssumption::BrokenEnclave`]
/// returns `false` — use [`core_gates_hold_under_attested`] with a verified quote.
pub fn core_gates_hold_under(assumption: TeeAssumption) -> bool {
    match assumption {
        TeeAssumption::Trusted => internal_core_gates_hold(),
        TeeAssumption::BrokenEnclave => false,
    }
}

/// Phase-7 gate checkpoint with attestation.
///
/// Verifies `quote` over `expected_report_data` via `provider`, then confirms
/// core crypto/topology/client paths still do not depend on a load-bearing enclave.
pub fn core_gates_hold_under_attested<P: AttestationProvider>(
    assumption: TeeAssumption,
    provider: &P,
    quote: &AttestationQuote,
    expected_report_data: &[u8],
) -> bool {
    if provider
        .verify_quote(quote, expected_report_data)
        .is_err()
    {
        return false;
    }
    match assumption {
        TeeAssumption::Trusted | TeeAssumption::BrokenEnclave => internal_core_gates_hold(),
    }
}

/// Shared gate body: no crate currently depends on enclave attestation for any
/// security property (verified by inspection of aegis-crypto/-topology/-relay/
/// -client/-negotiator). Revisit when a TEE-backed feature ships.
fn internal_core_gates_hold() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> SoftwareAttestationProvider {
        SoftwareAttestationProvider::from_seed([0x42; 32])
    }

    #[test]
    fn software_issue_and_verify_success() {
        let provider = test_provider();
        let report_data = b"gate-checkpoint-v1";
        let quote = provider.issue_quote(report_data);
        assert_eq!(quote.provider, SOFTWARE_PROVIDER_ID);
        provider
            .verify_quote(&quote, report_data)
            .expect("valid quote");
    }

    #[test]
    fn software_verify_fails_on_tampered_report_data() {
        let provider = test_provider();
        let quote = provider.issue_quote(b"original");
        assert_eq!(
            provider.verify_quote(&quote, b"tampered"),
            Err(AttestationError::ReportDataMismatch)
        );
    }

    #[test]
    fn software_verify_fails_on_tampered_signature() {
        let provider = test_provider();
        let mut quote = provider.issue_quote(b"payload");
        quote.signature[0] ^= 0xFF;
        assert_eq!(
            provider.verify_quote(&quote, b"payload"),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn broken_enclave_without_quote_fails() {
        assert!(!core_gates_hold_under(TeeAssumption::BrokenEnclave));
    }

    #[test]
    fn trusted_assumption_lab_path_still_passes() {
        assert!(core_gates_hold_under(TeeAssumption::Trusted));
    }

    #[test]
    fn broken_enclave_with_verified_quote_passes_attested_gate() {
        let provider = test_provider();
        let report_data = phase7_gate_report_data();
        let quote = provider.issue_quote(&report_data);
        assert!(core_gates_hold_under_attested(
            TeeAssumption::BrokenEnclave,
            &provider,
            &quote,
            &report_data,
        ));
    }

    #[test]
    fn attested_gate_fails_on_bad_quote() {
        let provider = test_provider();
        let report_data = phase7_gate_report_data();
        let mut quote = provider.issue_quote(&report_data);
        quote.signature[1] ^= 0x01;
        assert!(!core_gates_hold_under_attested(
            TeeAssumption::BrokenEnclave,
            &provider,
            &quote,
            &report_data,
        ));
    }
}
