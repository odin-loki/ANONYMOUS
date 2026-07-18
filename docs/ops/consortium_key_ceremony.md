# Consortium key ceremony (M-of-N)

**Status:** ops runbook + tooling (2026-07-18)  
**APIs:** `ConsortiumKey`, `ThresholdConsortium`, `ThresholdSignedRelayRecord` in `aegis-topology::roster`  
**Custody:** `SoftwareCustodyProvider` / `HsmCustodyProvider` / `SimulatedHsmProvider` + `Pkcs11CustodyOps` + `select_ceremony_custody` in `aegis-topology::custody`  
**Helper:** `cargo run -p aegis-topology --bin aegis-ceremony`  
**Shamir:** optional GF(256) share split/reconstruct in `aegis-topology::shamir` / `ceremony`  
**SoftHSM pilot:** [`softhsm_ceremony.md`](softhsm_ceremony.md) — WSL token init + PKCS#11 mapping (optional; not CI). Lab smoke without SoftHSM: `cargo test -p aegis-topology custody::tests::simulated_hsm_lab_only_roundtrip`

This ceremony produces the Ed25519 authority keys that sign permissioned
[`RelayRecord`](../../crates/aegis-topology/src/types.rs) admissions (including the
hybrid KEM public-key commitment). Nodes verify admissions with
`ThresholdConsortium` / `admit_threshold_signed`.

## Custody modes (`aegis-topology::custody`)

| Mode | Provider | Behavior on this build |
|------|----------|------------------------|
| `CeremonyCustodyMode::Software` | `SoftwareCustodyProvider` | Shamir split + file ceremony (default; CI/lab) |
| `CeremonyCustodyMode::Hardware` | `HsmCustodyProvider` | **Fail-closed** — `CeremonyError::HsmUnavailable` with PKCS#11 hint |
| Lab integration | `SimulatedHsmProvider` | HSM-shaped API over in-memory keys — **NOT hardware** |

```rust
use aegis_topology::{
    select_ceremony_custody, CeremonyCustodyMode, CeremonyError, Pkcs11CustodyOps,
    HsmCustodyProvider, SimulatedHsmProvider, SoftwareCustodyProvider,
};

// Lab default — same Shamir + aegis-ceremony path as today.
let provider: SoftwareCustodyProvider =
    select_ceremony_custody(CeremonyCustodyMode::Software)?;

// Production HSM wiring — fails closed until a vendor SDK is linked:
match select_ceremony_custody(CeremonyCustodyMode::Hardware) {
    Err(CeremonyError::HsmUnavailable(msg)) => eprintln!("{msg}"),
    Ok(_) => unreachable!(),
}

// Lab-only: exercise HSM-shaped call sites (never production)
let sim = SimulatedHsmProvider::new_lab_only();
let slots = sim.list_slots()?;
```

### PKCS#11 custody contract (`Pkcs11CustodyOps`)

When a PKCS#11 / vendor SDK is linked, [`HsmCustodyProvider`] must implement:

| Method | PKCS#11 analogue | Requirement |
|--------|------------------|-------------|
| [`list_slots`](../../crates/aegis-topology/src/custody.rs) | `C_GetSlotList` | Operator inventory of tokens/slots |
| [`generate_wrap_seed_share`](../../crates/aegis-topology/src/custody.rs) | `C_GenerateKeyPair` + wrap | Ed25519 key inside HSM; export wrapped Shamir share only ([`HsmWrappedShareFields`]) |
| [`sign_admission`](../../crates/aegis-topology/src/custody.rs) | `C_Sign` | [`AuthorityAdmissionSignature`] over [`RelayRecord`] without seed export |
| [`verify_wrapped_share`](../../crates/aegis-topology/src/custody.rs) | unwrap + metadata | Bind authority index, custodian id, Shamir x in wrap AAD |

This workspace deliberately has **no** PKCS#11 dependency; hardware mode always returns
`CeremonyError::HsmUnavailable` with [`hsm_unavailable_hint`](../../crates/aegis-topology/src/custody.rs).

### Simulated HSM (lab only)

[`SimulatedHsmProvider`](../../crates/aegis-topology/src/custody.rs) implements [`Pkcs11CustodyOps`] using in-memory
[`SoftwareCustodyProvider`](../../crates/aegis-topology/src/custody.rs) keys. Provider id: `simulated-hsm-lab-v1`.
**Do not deploy in production or claim hardware custody.**

## Prerequisites

- Offline or air-gapped machine preferred for seed generation
- Rust workspace build (`crates/`)
- Agreement on **N** (number of authorities) and **M** (threshold, `1 ≤ M ≤ N`)
- Secure offline storage for each authority's 32-byte signing seed
- Optional: Shamir share custodians (`shamir_n` / `shamir_threshold`) for seed custody

## Dry-run (no secrets written beyond temp)

```bash
cargo run -p aegis-topology --bin aegis-ceremony -- --help
```

## Generate keys + sample admission

```bash
cargo run -p aegis-topology --bin aegis-ceremony -- \
  --out ./ceremony-out \
  --n 3 \
  --threshold 2 \
  --jurisdiction US
```

### Optional Shamir M-of-N shares per authority seed

```bash
cargo run -p aegis-topology --bin aegis-ceremony -- \
  --out ./ceremony-out \
  --n 3 \
  --threshold 2 \
  --shamir-n 3 \
  --shamir-threshold 2
```

Each authority’s 32-byte seed is split with pure-Rust GF(256) Shamir into
`shamir_n` shares (reconstruction needs `shamir_threshold`). Share files are
written separately so each custodian receives only one share.

### Lab: reconstruct a seed from share files

```bash
cargo run -p aegis-topology --bin aegis-ceremony -- \
  --reconstruct \
    ceremony-out/authorities/authority-0/share-0.hex \
    ceremony-out/authorities/authority-0/share-1.hex \
  --reconstruct-out authority-0.seed.hex
```

APIs: `split_seed` / `reconstruct_seed` (`shamir`), `reconstruct_seed_from_files`
(`ceremony`).

### Output layout

| Path | Contents |
|------|----------|
| `authorities/authority-i.pub.hex` | 64-hex Ed25519 verifying key (safe to distribute) |
| `authorities/authority-i.seed.hex` | 64-hex signing seed (**secret**; offline / HSM; optional) |
| `authorities/authority-i/share-j.hex` | Shamir share (`xx` + 64 hex y); **secret**; one per custodian |
| `consortium.json` | Manifest: `threshold`, `n`, pubkey list, optional Shamir params |
| `sample_admission.json` | `ThresholdSignedRelayRecord` with M signatures (verified) |
| `roster_authority.toml.snippet` | Paste into `[roster]` for `aegis-node` / client |

Share hex format: 1-byte x-coordinate (`01`…`ff`) + 32-byte y (per-byte Shamir over AES GF(2⁸)).

## Manual ceremony steps (same APIs)

1. **Generate N keys** — each trustee runs locally (or the helper once offline):

   ```rust
   let key = ConsortiumKey::generate(&mut rng);
   let pubkey = key.verifying_key(); // distribute
   // Persist SigningKey seed offline; wrap with ConsortiumKey::from_signing_key
   // Optional: split_seed(&seed, shamir_t, shamir_n, &mut rng)
   ```

2. **Publish pubkeys** — collect all N verifying keys; agree on M.

3. **Configure consortium** on every node that loads a signed roster:

   ```toml
   [roster]
   path = "roster.json"
   threshold = 2
   authority_pubkeys = [
     "<hex pk 0>",
     "<hex pk 1>",
     "<hex pk 2>",
   ]
   ```

   Loaded via `ThresholdConsortium::from_raw_pubkeys(threshold, &keys)`.

4. **Admit a relay** — build a production record and collect M signatures:

   ```rust
   let record = RelayRecord::from_kem_public(jurisdiction, &kem_public);
   let mut signed = ThresholdSignedRelayRecord::new(record.clone());
   // Each of M authorities:
   signed = signed.with_signature(authority.sign_authority(&record));
   signed.verify_threshold(&consortium)?;
   roster.admit_threshold_signed(signed, &consortium, &mut ledger)?;
   ```

5. **Persist roster** — `RelayRoster::save_to_file`; loaders re-verify with the
   configured consortium (`allow_unverified_roster = false` in production).

6. **Seed hygiene** — never put `.seed.hex` or `share-*.hex` in git, backups, or
   node config. Rotate by generating a new N-set, re-signing active relays, then
   retiring old pubkeys from `[roster].authority_pubkeys`.

## Verification checklist

- [ ] `sample_admission.json` verifies with `verify_threshold` against the published pubkeys
- [ ] Node TOML `threshold` and `authority_pubkeys` match `consortium.json`
- [ ] At least M distinct authorities hold their seeds (or reconstructable Shamir sets) offline
- [ ] If Shamir enabled: each share held by a distinct custodian; fewer than `shamir_threshold` shares leak no seed
- [ ] Unsigned / unverified roster load is disabled in production

## Residual

Ceremony Shamir is **lab/ops custody** for 32-byte seeds. **In-tree:** `SoftwareCustodyProvider`,
`Pkcs11CustodyOps` + `HsmCustodyProvider` fail-closed stub, `SimulatedHsmProvider` (lab-only),
`select_ceremony_custody`. **External:** link PKCS#11 / vendor HSM SDK + interactive MPC ceremony;
not multi-party computation or proactive share refresh. Seeds/share files use mode `0600` on Unix.
Production operators should prefer HSMs where available and treat the helper as a bootstrap aid.
