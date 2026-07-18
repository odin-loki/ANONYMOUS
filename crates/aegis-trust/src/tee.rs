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
//! configured root key, **not** enclave integrity. [`HardwareTeeProvider`] is
//! the fail-closed hardware stub (returns [`TeeError::HardwareUnavailable`] on
//! hosts without a TEE SDK). Use [`select_attestation_provider`] to pick a mode.
//! See `docs/ops/tee_attestation.md`.
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

/// Provider id for hardware-backed quotes (Intel DCAP / AMD SEV-SNP).
pub const HARDWARE_PROVIDER_ID: &str = "hardware-tee-v1";

/// Canonical `report_data` for the Phase-7 gate checkpoint (lab / software path).
pub const PHASE7_GATE_REPORT_DOMAIN: &[u8] = b"AEGIS-PHASE7-GATE-v1";

/// Magic prefix for the minimal hardware quote wire envelope (format check only).
pub const HARDWARE_QUOTE_ENVELOPE_MAGIC: &[u8; 4] = b"ATQ1";

/// Envelope format version understood by [`parse_hardware_quote_envelope`].
pub const HARDWARE_QUOTE_ENVELOPE_VERSION: u8 = 1;

/// Maximum `report_data` length accepted by the envelope parser (64 KiB).
pub const HARDWARE_QUOTE_ENVELOPE_MAX_REPORT_DATA: u32 = 65_536;

/// Maximum opaque quote blob length accepted by the envelope parser (1 MiB).
pub const HARDWARE_QUOTE_ENVELOPE_MAX_QUOTE_BLOB: u32 = 1_048_576;

/// Whether the platform's attested enclave (if any) should be trusted for this
/// check. `BrokenEnclave` models the spec's threat model where a compromised
/// relay's enclave attestation cannot be relied upon at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TeeAssumption {
    Trusted,
    BrokenEnclave,
}

/// Hardware TEE platform selector for quote requests and error hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TeePlatform {
    /// Intel SGX via DCAP quoting library / AESM.
    IntelDcap = 0,
    /// AMD SEV-SNP guest attestation via PSP / guest firmware.
    AmdSevSnp = 1,
}

impl TeePlatform {
    /// Decode platform tag from envelope byte.
    pub fn from_envelope_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::IntelDcap),
            1 => Some(Self::AmdSevSnp),
            _ => None,
        }
    }

    /// Envelope wire tag for this platform.
    pub fn envelope_tag(self) -> u8 {
        self as u8
    }
}

/// Required fields for a hardware attestation quote (Intel SGX / AMD SEV-SNP).
///
/// # Contract (implementors MUST satisfy all invariants)
///
/// | Field | Intel SGX (DCAP) | AMD SEV-SNP | Verifier MUST |
/// |-------|------------------|-------------|---------------|
/// | [`enclave_measurement`](Self::enclave_measurement) | 32 B `MRENCLAVE` (SHA-256 of enclave build) | 32 B guest launch `measurement` / firmware digest | Pin allowed values per deployment; reject unknown builds |
/// | [`signer_measurement`](Self::signer_measurement) | 32 B `MRSIGNER` (SHA-256 of enclave signer) | 32 B `author_key` / signer digest per guest policy | Pin allowed signers; reject unknown signers |
/// | [`report_data`](Self::report_data) | Must equal caller binding in SGX `REPORTDATA` (first 64 B used; remainder zero) | Must equal SEV guest report `report_data` per firmware spec | Compare byte-for-byte to expected binding **before** trusting quote crypto |
/// | [`tcb_version`](Self::tcb_version) | CPU SVN + PCE SVN + QE identity (collateral-specific) | Guest SVN + reported TCB | Enforce minimum TCB / freshness policy; reject stale or revoked platforms |
///
/// **This struct documents semantics only.** [`HardwareTeeProvider`] does not
/// populate it until a real SDK is linked. Parsing an envelope with
/// [`parse_hardware_quote_envelope`] validates wire layout, **not** attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareQuoteFields {
    /// Intel SGX: `MRENCLAVE` (32 B SHA-256 of enclave build).
    /// AMD SEV-SNP: guest firmware `measurement` / launch digest.
    pub enclave_measurement: [u8; 32],
    /// Intel SGX: `MRSIGNER` (32 B SHA-256 of enclave signer).
    /// AMD SEV-SNP: `author_key` / signer digest per guest policy.
    pub signer_measurement: [u8; 32],
    /// Must equal the caller's `report_data` binding (SGX `REPORTDATA` first
    /// 64 B; SEV guest report `report_data` per firmware spec).
    pub report_data: Vec<u8>,
    /// Platform TCB / security version (SGX `MISCSELECT`+CPUSVN+PCESVN; SEV `guest_svn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcb_version: Option<Vec<u8>>,
}

impl HardwareQuoteFields {
    /// Returns `true` when `report_data` matches the caller's expected binding.
    pub fn report_data_matches(&self, expected: &[u8]) -> bool {
        self.report_data.as_slice() == expected
    }
}

/// Intel DCAP quote request placeholder — documents inputs for real SDK wiring.
///
/// Link Intel SGX DCAP (`libsgx_dcap_quoteverify`, `libdcap_quoteprov`) and
/// call from [`HardwareTeeProvider::request_dcap_quote`]. Until then every call
/// returns [`TeeError::HardwareUnavailable`] with an actionable hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DcapQuoteRequest {
    /// Caller-defined binding placed into SGX `REPORTDATA` (typically ≤ 64 B).
    pub report_data: Vec<u8>,
    /// Expected enclave identity for policy pin (optional at request time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_mrenclave: Option<[u8; 32]>,
    /// Expected signer identity for policy pin (optional at request time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_mrsigner: Option<[u8; 32]>,
}

/// AMD SEV-SNP guest attestation request placeholder.
///
/// Link AMD SEV-SNP guest attestation (PSP / `libsev-guest`) and call from
/// [`HardwareTeeProvider::request_sev_quote`]. Until then every call returns
/// [`TeeError::HardwareUnavailable`] with an actionable hint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevQuoteRequest {
    /// Caller-defined binding placed into the guest report `report_data` field.
    pub report_data: Vec<u8>,
    /// Expected launch measurement for policy pin (optional at request time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_measurement: Option<[u8; 32]>,
    /// Expected author key digest for policy pin (optional at request time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_author_key: Option<[u8; 32]>,
}

/// Parsed hardware quote wire envelope (layout validation only — not attestation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareQuoteEnvelope {
    pub platform: TeePlatform,
    pub report_data: Vec<u8>,
    pub quote_blob: Vec<u8>,
}

/// A signed attestation quote binding opaque `report_data` to an issuer.
///
/// Hardware providers populate [`HardwareQuoteFields`] semantics in `signature`
/// / collateral (DCAP quote blob, SEV cert chain). The software provider stores
/// an Ed25519 signature over `report_data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationQuote {
    /// Provider identifier (`software-v1`, `hardware-tee-v1`, etc.).
    pub provider: String,
    /// Opaque report payload the issuer attested to (caller-defined semantics).
    pub report_data: Vec<u8>,
    /// Provider-specific signature bytes (Ed25519 for software; DCAP/SEV quote for hardware).
    pub signature: Vec<u8>,
    /// Ed25519 verifying key (software provider only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey: Option<[u8; 32]>,
    /// Parsed hardware fields when `provider` is hardware-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hardware_fields: Option<HardwareQuoteFields>,
}

/// Attestation backend selection for ops / lab wiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationMode {
    /// Ed25519 software quotes — default for CI and local dev.
    Software,
    /// Hardware TEE quotes — fails closed when no platform SDK is present.
    Hardware,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TeeError {
    #[error("hardware TEE unavailable: {0}")]
    HardwareUnavailable(String),
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
    #[error("hardware quote envelope: {0}")]
    EnvelopeError(String),
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
            hardware_fields: None,
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

/// Serialize a minimal hardware quote envelope for wire transport.
///
/// Layout: `ATQ1` | version u8 | platform u8 | report_len u32 LE | quote_len u32 LE |
/// report_data | quote_blob. Does **not** perform attestation.
pub fn encode_hardware_quote_envelope(
    platform: TeePlatform,
    report_data: &[u8],
    quote_blob: &[u8],
) -> Result<Vec<u8>, AttestationError> {
    let report_len = u32::try_from(report_data.len())
        .map_err(|_| AttestationError::EnvelopeError("report_data too long".into()))?;
    let quote_len = u32::try_from(quote_blob.len())
        .map_err(|_| AttestationError::EnvelopeError("quote_blob too long".into()))?;
    if report_len > HARDWARE_QUOTE_ENVELOPE_MAX_REPORT_DATA {
        return Err(AttestationError::EnvelopeError(
            "report_data exceeds envelope limit".into(),
        ));
    }
    if quote_len > HARDWARE_QUOTE_ENVELOPE_MAX_QUOTE_BLOB {
        return Err(AttestationError::EnvelopeError(
            "quote_blob exceeds envelope limit".into(),
        ));
    }

    let mut out = Vec::with_capacity(14 + report_data.len() + quote_blob.len());
    out.extend_from_slice(HARDWARE_QUOTE_ENVELOPE_MAGIC);
    out.push(HARDWARE_QUOTE_ENVELOPE_VERSION);
    out.push(platform.envelope_tag());
    out.extend_from_slice(&report_len.to_le_bytes());
    out.extend_from_slice(&quote_len.to_le_bytes());
    out.extend_from_slice(report_data);
    out.extend_from_slice(quote_blob);
    Ok(out)
}

/// Parse and validate minimal hardware quote envelope structure.
///
/// Rejects truncated, oversized, or unknown-format blobs. **Does not verify
/// attestation** — use a vendor SDK (Intel QVL / AMD KDS) after parsing.
pub fn parse_hardware_quote_envelope(bytes: &[u8]) -> Result<HardwareQuoteEnvelope, AttestationError> {
    const HEADER_LEN: usize = 4 + 1 + 1 + 4 + 4;

    if bytes.len() < HEADER_LEN {
        return Err(AttestationError::EnvelopeError("truncated header".into()));
    }
    if bytes.get(0..4) != Some(HARDWARE_QUOTE_ENVELOPE_MAGIC) {
        return Err(AttestationError::EnvelopeError("bad magic".into()));
    }
    if bytes[4] != HARDWARE_QUOTE_ENVELOPE_VERSION {
        return Err(AttestationError::EnvelopeError("unsupported version".into()));
    }
    let platform = TeePlatform::from_envelope_tag(bytes[5])
        .ok_or_else(|| AttestationError::EnvelopeError("unknown platform tag".into()))?;

    let report_len = u32::from_le_bytes(bytes[6..10].try_into().expect("slice len"));
    let quote_len = u32::from_le_bytes(bytes[10..14].try_into().expect("slice len"));
    if report_len > HARDWARE_QUOTE_ENVELOPE_MAX_REPORT_DATA {
        return Err(AttestationError::EnvelopeError(
            "report_data length exceeds limit".into(),
        ));
    }
    if quote_len > HARDWARE_QUOTE_ENVELOPE_MAX_QUOTE_BLOB {
        return Err(AttestationError::EnvelopeError(
            "quote_blob length exceeds limit".into(),
        ));
    }

    let report_end = HEADER_LEN
        .checked_add(report_len as usize)
        .ok_or_else(|| AttestationError::EnvelopeError("report_data length overflow".into()))?;
    let total = report_end
        .checked_add(quote_len as usize)
        .ok_or_else(|| AttestationError::EnvelopeError("quote_blob length overflow".into()))?;
    if bytes.len() != total {
        return Err(AttestationError::EnvelopeError(format!(
            "length mismatch: header declares {total} bytes, got {}",
            bytes.len()
        )));
    }

    Ok(HardwareQuoteEnvelope {
        platform,
        report_data: bytes[HEADER_LEN..report_end].to_vec(),
        quote_blob: bytes[report_end..total].to_vec(),
    })
}

/// Actionable operator hint for linking a hardware TEE SDK.
pub fn hardware_unavailable_hint(platform: TeePlatform) -> &'static str {
    match platform {
        TeePlatform::IntelDcap => {
            "Intel DCAP unavailable: install SGX driver + AESM/PCCS, link \
             libsgx_dcap_quoteverify and libdcap_quoteprov (or intel-sgx-rs), \
             enable Cargo feature `tee-hardware`, and implement \
             HardwareTeeProvider::request_dcap_quote. See docs/ops/tee_attestation.md."
        }
        TeePlatform::AmdSevSnp => {
            "AMD SEV-SNP unavailable: enable SEV-SNP in firmware/BIOS, install \
             PSP packages, link libsev-guest (or sev crate), enable Cargo feature \
             `tee-hardware`, and implement HardwareTeeProvider::request_sev_quote. \
             See docs/ops/tee_attestation.md."
        }
    }
}

/// Hardware TEE attestation stub — fail-closed until a platform SDK is linked.
///
/// A production implementation must:
/// 1. Bind `report_data` into the hardware report (`REPORTDATA` / SEV guest report).
/// 2. Fetch a vendor quote (Intel DCAP QL / AMD PSP) containing
///    [`HardwareQuoteFields::enclave_measurement`] and
///    [`HardwareQuoteFields::signer_measurement`].
/// 3. Verify collateral (PCK certs, TCB, revocation) on the verifier side.
///
/// This host has no Intel SGX or AMD SEV-SNP SDK dependency; all entry points
/// return [`TeeError::HardwareUnavailable`] with [`hardware_unavailable_hint`].
pub struct HardwareTeeProvider;

impl HardwareTeeProvider {
    /// Probe for hardware TEE availability. Always fails on this build.
    pub fn try_new() -> Result<Self, TeeError> {
        Self::probe_hardware()
    }

    fn probe_hardware() -> Result<Self, TeeError> {
        // Real builds would detect /dev/sgx_enclave, SEV firmware, etc.
        Err(Self::hardware_unavailable(TeePlatform::IntelDcap))
    }

    pub(crate) fn hardware_unavailable(platform: TeePlatform) -> TeeError {
        TeeError::HardwareUnavailable(hardware_unavailable_hint(platform).to_string())
    }

    /// Issue a hardware quote binding `report_data`. Unavailable on this host.
    pub fn issue_quote(&self, _report_data: &[u8]) -> Result<AttestationQuote, TeeError> {
        Err(Self::hardware_unavailable(TeePlatform::IntelDcap))
    }

    /// Intel DCAP quote path — unavailable until DCAP SDK is linked.
    pub fn request_dcap_quote(&self, _req: &DcapQuoteRequest) -> Result<AttestationQuote, TeeError> {
        Err(Self::hardware_unavailable(TeePlatform::IntelDcap))
    }

    /// AMD SEV-SNP quote path — unavailable until SEV guest SDK is linked.
    pub fn request_sev_quote(&self, _req: &SevQuoteRequest) -> Result<AttestationQuote, TeeError> {
        Err(Self::hardware_unavailable(TeePlatform::AmdSevSnp))
    }

    /// Verify a hardware quote against `expected_report_data`. Unavailable on this host.
    pub fn verify_quote(
        &self,
        _quote: &AttestationQuote,
        _expected_report_data: &[u8],
    ) -> Result<(), TeeError> {
        Err(Self::hardware_unavailable(TeePlatform::IntelDcap))
    }

    /// Validate envelope layout then verify (both unavailable on this host).
    pub fn verify_envelope_quote(
        &self,
        envelope_bytes: &[u8],
        expected_report_data: &[u8],
    ) -> Result<(), TeeError> {
        let envelope = parse_hardware_quote_envelope(envelope_bytes)
            .map_err(|_| Self::hardware_unavailable(TeePlatform::IntelDcap))?;
        if envelope.report_data.as_slice() != expected_report_data {
            return Err(Self::hardware_unavailable(TeePlatform::IntelDcap));
        }
        self.verify_quote(
            &AttestationQuote {
                provider: HARDWARE_PROVIDER_ID.to_string(),
                report_data: envelope.report_data,
                signature: envelope.quote_blob,
                signer_pubkey: None,
                hardware_fields: None,
            },
            expected_report_data,
        )
    }
}

/// Select an attestation backend by mode.
///
/// - [`AttestationMode::Software`] — returns a [`SoftwareAttestationProvider`]
///   seeded from `software_seed` (lab default).
/// - [`AttestationMode::Hardware`] — fails closed with [`TeeError::HardwareUnavailable`]
///   when no platform TEE SDK is present (always on this workspace build).
pub fn select_attestation_provider(
    mode: AttestationMode,
    software_seed: [u8; 32],
) -> Result<SoftwareAttestationProvider, TeeError> {
    match mode {
        AttestationMode::Software => Ok(SoftwareAttestationProvider::from_seed(software_seed)),
        AttestationMode::Hardware => {
            HardwareTeeProvider::try_new()?;
            unreachable!("hardware probe succeeded but no provider wired")
        }
    }
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

    #[test]
    fn hardware_provider_fails_closed_on_this_host() {
        assert!(matches!(
            HardwareTeeProvider::try_new(),
            Err(TeeError::HardwareUnavailable(_))
        ));
    }

    #[test]
    fn hardware_dcap_request_fails_with_actionable_hint() {
        let req = DcapQuoteRequest {
            report_data: b"bind".to_vec(),
            expected_mrenclave: None,
            expected_mrsigner: None,
        };
        let err = HardwareTeeProvider.request_dcap_quote(&req);
        assert!(matches!(err, Err(TeeError::HardwareUnavailable(ref m)) if m.contains("DCAP")));
    }

    #[test]
    fn hardware_sev_request_fails_with_actionable_hint() {
        let req = SevQuoteRequest {
            report_data: b"bind".to_vec(),
            expected_measurement: None,
            expected_author_key: None,
        };
        let err = HardwareTeeProvider.request_sev_quote(&req);
        assert!(matches!(err, Err(TeeError::HardwareUnavailable(ref m)) if m.contains("SEV-SNP")));
    }

    #[test]
    fn hardware_quote_fields_report_data_binding() {
        let fields = HardwareQuoteFields {
            enclave_measurement: [1; 32],
            signer_measurement: [2; 32],
            report_data: b"expected".to_vec(),
            tcb_version: None,
        };
        assert!(fields.report_data_matches(b"expected"));
        assert!(!fields.report_data_matches(b"other"));
    }

    #[test]
    fn hardware_quote_envelope_roundtrip() {
        let report = b"phase7-bind";
        let blob = b"opaque-dcap-quote-bytes";
        let encoded =
            encode_hardware_quote_envelope(TeePlatform::IntelDcap, report, blob).expect("encode");
        let parsed = parse_hardware_quote_envelope(&encoded).expect("parse");
        assert_eq!(parsed.platform, TeePlatform::IntelDcap);
        assert_eq!(parsed.report_data, report);
        assert_eq!(parsed.quote_blob, blob);
    }

    #[test]
    fn hardware_quote_envelope_rejects_bad_magic() {
        let mut bad = encode_hardware_quote_envelope(TeePlatform::AmdSevSnp, b"x", b"y").unwrap();
        bad[0] ^= 0xFF;
        assert!(matches!(
            parse_hardware_quote_envelope(&bad),
            Err(AttestationError::EnvelopeError(_))
        ));
    }

    #[test]
    fn hardware_quote_envelope_rejects_truncated() {
        let encoded = encode_hardware_quote_envelope(TeePlatform::IntelDcap, b"a", b"b").unwrap();
        assert!(matches!(
            parse_hardware_quote_envelope(&encoded[..encoded.len() - 1]),
            Err(AttestationError::EnvelopeError(_))
        ));
    }

    #[test]
    fn select_attestation_provider_software_path() {
        let provider =
            select_attestation_provider(AttestationMode::Software, [0x42; 32]).expect("software");
        let report_data = b"select-test";
        let quote = provider.issue_quote(report_data);
        provider
            .verify_quote(&quote, report_data)
            .expect("software verify");
    }

    #[test]
    fn select_attestation_provider_hardware_fails_closed() {
        assert!(matches!(
            select_attestation_provider(AttestationMode::Hardware, [0; 32]),
            Err(TeeError::HardwareUnavailable(_))
        ));
    }
}
