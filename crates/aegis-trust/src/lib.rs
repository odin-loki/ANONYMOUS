//! # aegis-trust — Phase 7 (trust/attestation)
//!
//! Spec §4.8, §10 Phase-7 gate: "core gates hold with TEE assumed broken", ZK
//! reputation (scoped, non-PQ), Izaac/GRIA-style anomaly detection.
//!
//! ## Honest scope of this pass
//!
//! This is the most research-heavy phase in the build plan and is treated here
//! accordingly: real, working pieces are implemented where they don't require
//! novel cryptographic research; pieces that DO (a real TEE/DCAP attestation
//! flow) are left as clearly-marked interface boundaries rather than faked.
//! [`zk`] ships a genuine Bulletproofs range-proof implementation for
//! threshold membership plus a plaintext reference stand-in for wiring tests.
//!
//! Modules:
//! - [`reputation`] — real, working EWMA reputation ledger (the non-ZK
//!   bookkeeping a future ZK circuit would sit in front of).
//! - [`zk`] — Bulletproofs range proof for threshold membership, anonymous
//!   presentation (no RelayId in proof bytes), + plaintext stand-in.
//! - [`nullifier`] — local/file-backed spent-nullifier registry (replay prevention
//!   per epoch; not a multi-node AC issuer).
//! - [`anon_issuer`] — minimal software-bound [`AnonymousCredentialIssuer`]
//!   (Partial; not a full interactive AC / real ZK show protocol).
//! - [`tee`] — TEE-broken-enclave assumption bookkeeping, attestation provider
//!   interface, and the Phase-7 gate check.
//! - [`anomaly`] — a generic EWMA/z-score anomaly detector as a stand-in for the
//!   spec's Izaac/GRIA reference (NOT a reproduction of that specific published
//!   method — see module docs).
//! - [`policy`] — wires anomaly verdicts into reputation demotion for path pruning.

pub mod anomaly;
pub mod anon_issuer;
pub mod nullifier;
pub mod policy;
pub mod reputation;
pub mod tee;
pub mod zk;

pub use anomaly::{AnomalyDetector, AnomalyVerdict};
pub use anon_issuer::{
    AnonymousCredentialIssuer, AnonymousCredentialIssuerParams, IssuedAnonymousCredential,
    IssuerError,
};
pub use nullifier::{NullifierError, NullifierRegistry};
pub use policy::{feed_peer_metric, feed_peer_outcomes, RelayPruningPolicy, DEFAULT_PATH_REPUTATION_FLOOR};
pub use reputation::{
    signing_key_from_hex_seed, signing_key_from_seed, verifying_key_from_hex, ReputationError,
    ReputationLedger, ReputationScore,
};
pub use tee::{
    core_gates_hold_under, core_gates_hold_under_attested, phase7_gate_report_data,
    select_attestation_provider, AttestationError, AttestationMode, AttestationProvider,
    AttestationQuote, HardwareQuoteFields, HardwareTeeProvider, SoftwareAttestationProvider,
    TeeAssumption, TeeError, HARDWARE_PROVIDER_ID, PHASE7_GATE_REPORT_DOMAIN,
    SOFTWARE_PROVIDER_ID,
};
pub use zk::{
    derive_reputation_nullifier, present_anonymous, scale_reputation, verify_anonymous,
    verify_anonymous_and_spend, AnonymousReputationPresentation, BulletproofsProof,
    BulletproofsReputationProof, PlaintextReputationProof, ReputationNullifier,
    ZkReputationProof, RANGE_BITS, SCORE_SCALE,
};
