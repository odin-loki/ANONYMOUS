# TEE attestation plug-in (ops)

**Status:** Partial (2026-07-18) — real interface + software lab provider + fail-closed hardware stub + envelope parser; no Intel SGX / AMD SEV SDK linked yet.

## What ships today

| Component | Location | Purpose |
|-----------|----------|---------|
| [`AttestationProvider`](../../crates/aegis-trust/src/tee.rs) trait | `aegis-trust::tee` | Issue/verify quotes over opaque `report_data` |
| [`SoftwareAttestationProvider`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Ed25519-signed quotes for lab/tests (**default**) |
| [`HardwareTeeProvider`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Fail-closed hardware stub — [`TeeError::HardwareUnavailable`] with actionable DCAP/SEV hints |
| [`DcapQuoteRequest`](../../crates/aegis-trust/src/tee.rs) / [`SevQuoteRequest`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Placeholder request types documenting Intel/AMD wiring |
| [`HardwareQuoteFields`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Documented contract: MRENCLAVE/MRSIGNER (SGX) or measurement/signer (SEV) + `report_data` binding |
| [`parse_hardware_quote_envelope`](../../crates/aegis-trust/src/tee.rs) | `aegis-trust::tee` | Wire layout validation only (`ATQ1` envelope) — **not attestation** |
| [`tee_hardware`](../../crates/aegis-trust/src/tee_hardware.rs) (feature `tee-hardware`) | `aegis-trust` | SDK hook module; still fail-closed without native libs |
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

// Production hardware path — fails closed with actionable hint
match select_attestation_provider(AttestationMode::Hardware, [0; 32]) {
    Err(TeeError::HardwareUnavailable(msg)) => eprintln!("{msg}"),
    Ok(_) => unreachable!(),
}
```

## Hardware quote envelope (format check only)

Operators may wrap opaque DCAP/SEV quote blobs in the AEGIS `ATQ1` envelope for transport. Parsing validates magic, version, platform tag, and length bounds — it **does not** verify attestation.

```rust
use aegis_trust::{
    encode_hardware_quote_envelope, parse_hardware_quote_envelope, TeePlatform,
};

let wire = encode_hardware_quote_envelope(TeePlatform::IntelDcap, b"bind", b"opaque-quote")?;
let env = parse_hardware_quote_envelope(&wire)?;
assert_eq!(env.report_data, b"bind");
// Still need Intel QVL / AMD KDS for crypto verification.
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

Enable Cargo feature `tee-hardware` on `aegis-trust` and implement inside [`HardwareTeeProvider`](../../crates/aegis-trust/src/tee.rs) (or `tee_hardware`):

1. **`request_dcap_quote(DcapQuoteRequest)`** — Intel path:
   - Bind `report_data` into SGX `REPORTDATA`.
   - Fetch DCAP quote via quoting library / AESM.
   - Populate [`HardwareQuoteFields`](../../crates/aegis-trust/src/tee.rs) and return `AttestationQuote` with `provider = hardware-tee-v1`.

2. **`request_sev_quote(SevQuoteRequest)`** — AMD path:
   - Bind `report_data` into guest report.
   - Fetch SEV-SNP quote via PSP / guest firmware.
   - Populate [`HardwareQuoteFields`](../../crates/aegis-trust/src/tee.rs) per SEV semantics.

3. **`verify_quote(quote, expected_report_data)`** — verifier side:
   - Run vendor SDK (Intel QVL / DCAP, AMD KDS).
   - Check `hardware_fields.report_data` matches `expected_report_data`.
   - Pin allowed measurements / signers and TCB policy.

4. **Probe** — wire `HardwareTeeProvider::probe_hardware()` to detect `/dev/sgx_enclave`, SEV firmware, etc.

Until SDKs are linked, all hardware paths return [`TeeError::HardwareUnavailable`](../../crates/aegis-trust/src/tee.rs) with [`hardware_unavailable_hint`](../../crates/aegis-trust/src/tee.rs) text (no fake quotes).

## Residual

| Item | Status |
|------|--------|
| Hardware quote issuance/verification | **External** — link Intel DCAP / AMD SEV-SNP SDK + platform device |
| Envelope parse/validate | **Done** — layout only, no crypto |
| `DcapQuoteRequest` / `SevQuoteRequest` placeholders | **Done** |
| Software provider | **Done** — lab/tests (default via `AttestationMode::Software`) |
| Hardware mode selector | **Done** — fail-closed with actionable hints |
| Phase-7 gate without quote under `BrokenEnclave` | **Fails closed** — by design |
| Core crypto independent of TEE | **Holds** — no load-bearing enclave dependency in workspace crates |

See also: `docs/AEGIS_implementation_threat_model.md` §4 (`aegis-trust`), workstream #1 in `docs/AEGIS_research_ops_hardening_plan.md`.
