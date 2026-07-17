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
//! - [`zk`] — Bulletproofs range proof for threshold membership + plaintext stand-in.
//! - [`tee`] — TEE-broken-enclave assumption bookkeeping and the Phase-7 gate
//!   check (currently vacuous — see module docs for why, honestly).
//! - [`anomaly`] — a generic EWMA/z-score anomaly detector as a stand-in for the
//!   spec's Izaac/GRIA reference (NOT a reproduction of that specific published
//!   method — see module docs).
//! - [`policy`] — wires anomaly verdicts into reputation demotion for path pruning.

pub mod anomaly;
pub mod policy;
pub mod reputation;
pub mod tee;
pub mod zk;

pub use anomaly::{AnomalyDetector, AnomalyVerdict};
pub use policy::{RelayPruningPolicy, DEFAULT_PATH_REPUTATION_FLOOR};
pub use reputation::{ReputationError, ReputationLedger, ReputationScore};
pub use tee::{core_gates_hold_under, TeeAssumption};
pub use zk::{
    BulletproofsProof, BulletproofsReputationProof, PlaintextReputationProof, ZkReputationProof,
    RANGE_BITS, SCORE_SCALE, scale_reputation,
};
