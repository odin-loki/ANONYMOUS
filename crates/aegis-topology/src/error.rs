//! Topology error types.

use thiserror::Error;

use crate::types::RelayId;

#[derive(Debug, Error, PartialEq)]
pub enum TopologyError {
    #[error("no admitted relays on roster")]
    EmptyRoster,

    #[error("layer count must be at least 1, got {0}")]
    InvalidLayerCount(usize),

    #[error("layer {layer} is empty in epoch {epoch}")]
    EmptyLayer { layer: usize, epoch: u64 },

    #[error("relay {relay:?} is not admitted")]
    NotAdmitted { relay: RelayId },

    #[error("not enough layer-1 relays ({available}) for {needed} guards")]
    InsufficientGuards { available: usize, needed: usize },

    #[error("relay {relay:?} not found in roster")]
    RelayNotFound { relay: RelayId },

    #[error(
        "not enough relays above reputation floor {min_reputation} ({available} available, {needed} needed)"
    )]
    InsufficientReputation {
        available: usize,
        needed: usize,
        min_reputation: f64,
    },

    #[error("could not select a reputation-compliant path after {attempts} attempts")]
    ReputationPathExhausted { attempts: usize },
}

/// Errors from signed admission and roster persistence (spec §4.9).
#[derive(Debug, Error)]
pub enum RosterError {
    #[error("invalid admission signature for relay {relay:?}")]
    InvalidSignature { relay: RelayId },

    #[error("admission authority public key mismatch")]
    AuthorityMismatch,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("deserialize error: {0}")]
    Deserialize(String),

    #[error(
        "admission rate limit exceeded: {attempted} admissions in window (max {max_per_window} per {window_secs}s)"
    )]
    AdmissionRateLimitExceeded {
        attempted: usize,
        max_per_window: usize,
        window_secs: u64,
    },

    #[error("insufficient consortium signatures: got {got}, need {need}")]
    InsufficientSignatures { got: usize, need: usize },

    #[error("duplicate admission signature from the same consortium authority")]
    DuplicateAuthority,

    #[error("admission signature from unknown consortium authority")]
    UnknownAuthority,

    #[error("relay {relay:?} blocked from admission: anomaly demotion below reputation floor")]
    AnomalyBlockedAdmission { relay: RelayId },

    #[error(
        "relay id does not match KEM-derived id for commitment \
         (expected RelayId::from_kem_commitment)"
    )]
    RelayIdCommitmentMismatch { relay: RelayId },

    #[error(
        "roster load requires consortium authority keys for signature re-verify, \
         or allow_unverified_roster=true (lab/test only)"
    )]
    UnverifiedRosterNotAllowed,

    #[error("invalid consortium authority public key bytes")]
    InvalidAuthorityPubkey,
}
