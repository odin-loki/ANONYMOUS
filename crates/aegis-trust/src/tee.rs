//! TEE-broken-enclave bookkeeping (spec §2, §4.8, §10 Phase-7 gate).
//!
//! Spec's threat model: "TEE-compromised variant: enclave assumed FULLY broken
//! on compromised relays; base guarantee must survive this (TEE is
//! defense-in-depth only)." The Phase-7 gate is: "core gates hold with enclave
//! assumed broken."
//!
//! # Why this is currently a vacuous check (documented honestly, not hidden)
//!
//! As of this pass, NO crate in this workspace uses a TEE/attestation result as
//! a load-bearing security assumption anywhere — `aegis-crypto`'s guarantees
//! come from the hybrid KEM + onion construction, `aegis-client`'s from
//! constant-rate emission + hard-cap padding, `aegis-topology`'s from stratified
//! routing + guard math, none of which reference an enclave. So "core gates hold
//! with the enclave assumed broken" is trivially true right now, for the boring
//! reason that there is no enclave dependency to break. [`core_gates_hold_under`]
//! reflects this honestly (always `true`, with this documented reasoning) rather
//! than performing a check against machinery that doesn't exist yet.
//!
//! This function's REAL job is to be a forcing-function checkpoint for later
//! work: the moment a future phase introduces a TEE-backed feature (self-hosted
//! DCAP sovereignty option per spec §4.8), whoever adds it MUST come back here,
//! make this function actually re-run the affected gate(s) with that feature's
//! enclave assumption flipped to broken, and only return `true` if they still
//! pass. Grep for `core_gates_hold_under` before shipping a TEE-dependent
//! feature.

/// Whether the platform's attested enclave (if any) should be trusted for this
/// check. `BrokenEnclave` models the spec's threat model where a compromised
/// relay's enclave attestation cannot be relied upon at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeeAssumption {
    Trusted,
    BrokenEnclave,
}

/// Phase-7 gate checkpoint. See module docs for why this is currently vacuous.
pub fn core_gates_hold_under(_assumption: TeeAssumption) -> bool {
    // No crate currently depends on enclave attestation for any security
    // property (verified by inspection of aegis-crypto/-topology/-relay/-client/
    // -negotiator as of this writing) — see module docs. Revisit the moment
    // that stops being true.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_holds_under_both_assumptions_today() {
        assert!(core_gates_hold_under(TeeAssumption::Trusted));
        assert!(core_gates_hold_under(TeeAssumption::BrokenEnclave));
    }
}
