//! Hardware TEE integration hooks (feature `tee-hardware`).
//!
//! This module does **not** link Intel DCAP or AMD SEV-SNP SDKs. It documents
//! the request/response shapes operators wire when enabling real attestation.
//! All entry points remain fail-closed until a platform SDK is linked.

use crate::tee::{
    AttestationQuote, DcapQuoteRequest, HardwareTeeProvider, SevQuoteRequest, TeeError,
};

/// Intel DCAP quote request — fails closed on this build.
pub fn request_dcap_quote(req: &DcapQuoteRequest) -> Result<AttestationQuote, TeeError> {
    HardwareTeeProvider.request_dcap_quote(req)
}

/// AMD SEV-SNP quote request — fails closed on this build.
pub fn request_sev_quote(req: &SevQuoteRequest) -> Result<AttestationQuote, TeeError> {
    HardwareTeeProvider.request_sev_quote(req)
}
