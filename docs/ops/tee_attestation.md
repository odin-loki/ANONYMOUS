# TEE attestation plug-in (ops)

**Status:** Partial (2026-07-17) — real interface + software lab provider; no hardware enclave SDK yet.

## What ships today

| Component | Location | Purpose |
|-----------|----------|---------|
| [`AttestationProvider`](../../crates/aegis-trust/src/tee.rs) trait | `aegis-trust::tee` | Issue/verify quotes over opaque `report_data` |
| [`SoftwareAttestationProvider`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Ed25519-signed quotes for lab/tests |
| [`core_gates_hold_under_attested`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Phase-7 gate with verified quote |
| [`core_gates_hold_under`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | **Lab only** — `Trusted` assumption, no quote |

## Software provider — what it proves (and does not)

**Proves:** whoever holds the configured Ed25519 signing key attested to a specific `report_data` blob at quote issuance time.

**Does not prove:**

- That code ran inside a hardware enclave (SGX, SEV-SNP, TDX, etc.)
- That the enclave measurement (MRENCLAVE, image hash) matches an expected value
- That the platform TCB / firmware is up to date
- That a compromised host OS has not tampered with the “enclave”

Use [`SoftwareAttestationProvider`](../../crates/aegis-trust/src/tee.rs) only in CI, local dev, and integration tests. Production relays that advertise TEE defense-in-depth must use a hardware-backed provider.

## Lab workflow

```rust
use aegis_trust::{
    core_gates_hold_under_attested, phase7_gate_report_data, SoftwareAttestationProvider,
    TeeAssumption,
};

let provider = SoftwareAttestationProvider::from_seed([0x42; 32]); // lab root — rotate in prod
let report_data = phase7_gate_report_data();
let quote = provider.issue_quote(&report_data);

assert!(core_gates_hold_under_attested(
    TeeAssumption::BrokenEnclave,
    &provider,
    &quote,
    &report_data,
));
```

`core_gates_hold_under(TeeAssumption::BrokenEnclave)` returns **`false`** without a quote — callers must use the attested API.

## Plugging in SGX / AMD SEV later

Implement [`AttestationProvider`](../../crates/aegis-trust/src/tee.rs) for your stack:

1. **`issue_quote(report_data)`** — inside the enclave (or via local quoting enclave):
   - Bind `report_data` into the hardware report (SGX: `REPORTDATA` field; SEV: guest report `report_data`).
   - Fetch a quote from the platform (DCAP / AESM for Intel; PSP / guest firmware for AMD).
   - Return an [`AttestationQuote`](../../crates/aegis-trust/src/tee.rs) with a new `provider` id (e.g. `sgx-dcap-v1`) and provider-specific `signature` / collateral fields as needed.

2. **`verify_quote(quote, expected_report_data)`** — on the verifier (relay operator, consortium auditor):
   - Verify the quote with the vendor SDK (Intel QVL / DCAP, AMD KDS, etc.).
   - Check `report_data` matches `expected_report_data` (and any enclave measurement policy your deployment pins).
   - Reject stale TCB / revoked platforms per your ops policy.

3. **Gate wiring** — call `core_gates_hold_under_attested` at the Phase-7 checkpoint with your provider instance and the same `expected_report_data` used at issuance.

Suggested extension points (not implemented yet):

- Collateral blobs (PCK certs, CRLs) attached to `AttestationQuote` via serde fields or a sidecar.
- Policy struct: allowed MRENCLAVE set, minimum TCB, quote freshness window.
- Separate verify-only type (`AttestationVerifier`) if issuance and verification keys diverge on different nodes.

## Residual

| Item | Status |
|------|--------|
| Hardware quote issuance/verification | **Open** — interface only |
| Software provider | **Done** — lab/tests |
| Phase-7 gate without quote under `BrokenEnclave` | **Fails closed** — by design |
| Core crypto independent of TEE | **Holds** — no load-bearing enclave dependency in workspace crates |

See also: `docs/AEGIS_implementation_threat_model.md` §4 (`aegis-trust`), workstream #1 in `docs/AEGIS_research_ops_hardening_plan.md`.
