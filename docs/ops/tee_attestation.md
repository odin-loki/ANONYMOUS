# TEE attestation plug-in (ops)

**Status:** Partial (2026-07-17) — real interface + software lab provider + fail-closed hardware stub; no Intel SGX / AMD SEV SDK linked yet.

## What ships today

| Component | Location | Purpose |
|-----------|----------|---------|
| [`AttestationProvider`](../../crates/aegis-trust/src/tee.rs) trait | `aegis-trust::tee` | Issue/verify quotes over opaque `report_data` |
| [`SoftwareAttestationProvider`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Ed25519-signed quotes for lab/tests (**default**) |
| [`HardwareTeeProvider`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Fail-closed hardware stub — [`TeeError::HardwareUnavailable`] on this build |
| [`HardwareQuoteFields`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Documents MRENCLAVE/MRSIGNER (SGX) or measurement/signer (SEV) + `report_data` binding |
| [`select_attestation_provider`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | `Software` \| `Hardware` mode selector (hardware fails closed) |
| [`core_gates_hold_under_attested`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Phase-7 gate with verified quote |
| [`core_gates_hold_under`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | **Lab only** — `Trusted` assumption, no quote |

## Software provider — what it proves (and does not)

**Proves:** whoever holds the configured Ed25519 signing key attested to a specific `report_data` blob at quote issuance time.

**Does not prove:**

- That code ran inside a hardware enclave (SGX, SEV-SNP, TDX, etc.)
- That the enclave measurement (MRENCLAVE, image hash) matches an expected value
- That the platform TCB / firmware is up to date
- That a compromised host OS has not tampered with the “enclave”

Use [`SoftwareAttestationProvider`](../../crates/aegis-trust/src/tee.rs) only in CI, local dev, and integration tests. Production relays that advertise TEE defense-in-depth must use a hardware-backed provider once an SDK is linked — **never** fake hardware quotes on non-TEE hosts.

## Mode selection

```rust
use aegis_trust::{select_attestation_provider, AttestationMode, TeeError};

// Lab default — software quotes
let provider = select_attestation_provider(AttestationMode::Software, [0x42; 32])?;

// Production hardware path — fails closed on hosts without TEE SDK
assert_eq!(
    select_attestation_provider(AttestationMode::Hardware, [0; 32]),
    Err(TeeError::HardwareUnavailable),
);
```

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

Implement hardware issuance inside [`HardwareTeeProvider`](../../crates/aegis-trust/src/tee.rs) (or a sibling type implementing [`AttestationProvider`](../../crates/aegis-trust/src/tee.rs)):

1. **`issue_quote(report_data)`** — inside the enclave (or via local quoting enclave):
   - Bind `report_data` into the hardware report (SGX: `REPORTDATA` field; SEV: guest report `report_data`).
   - Fetch a quote from the platform (DCAP / AESM for Intel; PSP / guest firmware for AMD).
   - Populate [`HardwareQuoteFields`](../../crates/aegis-trust/src/tee.rs):
     - **`enclave_measurement`** — SGX `MRENCLAVE` or SEV launch measurement
     - **`signer_measurement`** — SGX `MRSIGNER` or SEV author key digest
     - **`report_data`** — must match the caller binding byte-for-byte
     - **`tcb_version`** — platform security version for freshness / revocation policy
   - Return an [`AttestationQuote`](../../crates/aegis-trust/src/tee.rs) with `provider = hardware-tee-v1`, DCAP/SEV quote bytes in `signature`, and `hardware_fields` set.

2. **`verify_quote(quote, expected_report_data)`** — on the verifier (relay operator, consortium auditor):
   - Verify the quote with the vendor SDK (Intel QVL / DCAP, AMD KDS, etc.).
   - Check `hardware_fields.report_data` matches `expected_report_data`.
   - Pin allowed `enclave_measurement` / `signer_measurement` sets per deployment.
   - Reject stale TCB / revoked platforms per your ops policy.

3. **Gate wiring** — call `core_gates_hold_under_attested` at the Phase-7 checkpoint with your provider instance and the same `expected_report_data` used at issuance.

4. **Probe** — wire `HardwareTeeProvider::probe_hardware()` to detect `/dev/sgx_enclave`, SEV firmware, etc.; until then the stub returns [`TeeError::HardwareUnavailable`] (no fake quotes).

Suggested extension points (not implemented yet):

- Collateral blobs (PCK certs, CRLs) attached to `AttestationQuote` via serde fields or a sidecar.
- Policy struct: allowed MRENCLAVE set, minimum TCB, quote freshness window.
- Separate verify-only type (`AttestationVerifier`) if issuance and verification keys diverge on different nodes.

## Residual

| Item | Status |
|------|--------|
| Hardware quote issuance/verification | **Open** — [`HardwareTeeProvider`](../../crates/aegis-trust/src/tee.rs) fail-closed stub + [`HardwareQuoteFields`](../../crates/aegis-trust/src/tee.rs) contract |
| Software provider | **Done** — lab/tests (default via `AttestationMode::Software`) |
| Hardware mode selector | **Done** — `select_attestation_provider` returns `TeeError::HardwareUnavailable` |
| Phase-7 gate without quote under `BrokenEnclave` | **Fails closed** — by design |
| Core crypto independent of TEE | **Holds** — no load-bearing enclave dependency in workspace crates |

See also: `docs/AEGIS_implementation_threat_model.md` §4 (`aegis-trust`), workstream #1 in `docs/AEGIS_research_ops_hardening_plan.md`.
