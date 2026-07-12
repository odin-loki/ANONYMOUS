//! # aegis-trust — Phase 7 (trust/attestation)
//!
//! Spec §4.8, §10 Phase-7 gate: "core gates hold with TEE assumed broken", ZK
//! reputation (scoped, non-PQ), Izaac/GRIA-style anomaly detection.
//!
//! ## Honest scope of this pass
//!
//! This is the most research-heavy phase in the build plan and is treated here
//! accordingly: real, working pieces are implemented where they don't require
//! novel cryptographic research; pieces that DO (a genuine ZK circuit, a real
//! TEE/DCAP attestation flow) are left as clearly-marked interface boundaries
//! rather than faked. Per this project's own governing principle (see the
//! workspace README: "nothing is done until an attack simulation confirms it" /
//! `aegis-crypto`'s "half-implemented crypto is worse than clearly-absent
//! crypto"), a shallow ZK-shaped wrapper around a plaintext check would be
//! actively misleading, so [`zk`] ships only a trait plus a plaintext reference
//! implementation that is explicitly labeled non-private.
//!
//! Modules:
//! - [`reputation`] — real, working EWMA reputation ledger (the non-ZK
//!   bookkeeping a future ZK circuit would sit in front of).
//! - [`zk`] — the ZK proof interface boundary + a labeled plaintext stand-in.
//! - [`tee`] — TEE-broken-enclave assumption bookkeeping and the Phase-7 gate
//!   check (currently vacuous — see module docs for why, honestly).
//! - [`anomaly`] — a generic EWMA/z-score anomaly detector as a stand-in for the
//!   spec's Izaac/GRIA reference (NOT a reproduction of that specific published
//!   method — see module docs).

pub mod anomaly;
pub mod reputation;
pub mod tee;
pub mod zk;

pub use anomaly::{AnomalyDetector, AnomalyVerdict};
pub use reputation::{ReputationError, ReputationLedger, ReputationScore};
pub use tee::{core_gates_hold_under, TeeAssumption};
pub use zk::{PlaintextReputationProof, ZkReputationProof};
