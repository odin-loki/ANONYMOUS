# Consortium key ceremony (M-of-N)

**Status:** ops runbook + tooling (2026-07-17)  
**APIs:** `ConsortiumKey`, `ThresholdConsortium`, `ThresholdSignedRelayRecord` in `aegis-topology::roster`  
**Helper:** `cargo run -p aegis-topology --bin aegis-ceremony`

This ceremony produces the Ed25519 authority keys that sign permissioned
[`RelayRecord`](../../crates/aegis-topology/src/types.rs) admissions (including the
hybrid KEM public-key commitment). Nodes verify admissions with
`ThresholdConsortium` / `admit_threshold_signed`.

## Prerequisites

- Offline or air-gapped machine preferred for seed generation
- Rust workspace build (`crates/`)
- Agreement on **N** (number of authorities) and **M** (threshold, `1 ≤ M ≤ N`)
- Secure offline storage for each authority's 32-byte signing seed

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

### Output layout

| Path | Contents |
|------|----------|
| `authorities/authority-i.pub.hex` | 64-hex Ed25519 verifying key (safe to distribute) |
| `authorities/authority-i.seed.hex` | 64-hex signing seed (**secret**; offline / HSM) |
| `consortium.json` | Manifest: `threshold`, `n`, pubkey list |
| `sample_admission.json` | `ThresholdSignedRelayRecord` with M signatures (verified) |
| `roster_authority.toml.snippet` | Paste into `[roster]` for `aegis-node` / client |

## Manual ceremony steps (same APIs)

1. **Generate N keys** — each trustee runs locally (or the helper once offline):

   ```rust
   let key = ConsortiumKey::generate(&mut rng);
   let pubkey = key.verifying_key(); // distribute
   // Persist SigningKey seed offline; wrap with ConsortiumKey::from_signing_key
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

6. **Seed hygiene** — never put `.seed.hex` in git, backups, or node config.
   Rotate by generating a new N-set, re-signing active relays, then retiring old
   pubkeys from `[roster].authority_pubkeys`.

## Verification checklist

- [ ] `sample_admission.json` verifies with `verify_threshold` against the published pubkeys
- [ ] Node TOML `threshold` and `authority_pubkeys` match `consortium.json`
- [ ] At least M distinct authorities hold their seeds offline
- [ ] Unsigned / unverified roster load is disabled in production

## Residual

Ceremony tooling does **not** provide Shamir secret sharing, HSM integration, or
multi-party computation. Seeds are hex files (mode `0600` on Unix). Production
operators should move seeds into HSMs and treat the helper as a lab/bootstrap aid.
