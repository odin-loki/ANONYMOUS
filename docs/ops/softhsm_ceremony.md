# SoftHSM2 ceremony pilot (PKCS#11)

**Status:** ops pilot runbook (2026-07-18) — **not required for CI**  
**Parent:** [`consortium_key_ceremony.md`](consortium_key_ceremony.md)  
**APIs:** `Pkcs11CustodyOps`, `HsmCustodyProvider`, `SimulatedHsmProvider`, `select_ceremony_custody`

This document is the operator path for standing up **SoftHSM2** under WSL/Linux as a
PKCS#11 stand-in before linking a vendor HSM. The in-tree Rust workspace remains
**fail-closed** for `CeremonyCustodyMode::Hardware` until `HsmCustodyProvider` is wired
to a real module.

## Lab vs pilot vs production

| Path | Provider | Use |
|------|----------|-----|
| CI / default dev | `SoftwareCustodyProvider` | Shamir + `aegis-ceremony` files |
| Lab HSM-shaped tests | `SimulatedHsmProvider` | Exercise `Pkcs11CustodyOps` without hardware |
| **This pilot** | SoftHSM2 + future `HsmCustodyProvider` | Operator PKCS#11 token init + slot inventory |
| Production | Vendor HSM (Luna, YubiHSM, …) | Same contract as SoftHSM pilot |

**Do not** claim hardware custody with SoftHSM or `SimulatedHsmProvider`.

## Install (WSL / Debian-family Linux)

```bash
sudo apt-get update
sudo apt-get install -y softhsm2 opensc
```

Common module path (set `AEGIS_PKCS11_MODULE` if different):

```text
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

## Init token (safe helper)

From repo root:

```bash
bash scripts/softhsm_init.sh
```

If `softhsm2-util` is missing, the script prints an install hint and exits **0**
(so CI/agents without SoftHSM do not fail).

Environment overrides:

| Variable | Default | Purpose |
|----------|---------|---------|
| `AEGIS_SOFTHSM_SLOT` | `0` | Token slot |
| `AEGIS_SOFTHSM_TOKEN_LABEL` | `aegis-ceremony` | Token label |
| `AEGIS_SOFTHSM_SO_PIN` / `AEGIS_SOFTHSM_USER_PIN` | `1234` | **Change in real ops** |
| `SOFTHSM2_CONF` | `~/.config/softhsm2/softhsm2.conf` | SoftHSM config file |
| `AEGIS_PKCS11_MODULE` | see above | PKCS#11 module for `pkcs11-tool` smoke |

Manual equivalent:

```bash
export SOFTHSM2_CONF="$HOME/.config/softhsm2/softhsm2.conf"
softhsm2-util --init-token --slot 0 --label "aegis-ceremony" \
  --so-pin "$SO_PIN" --pin "$USER_PIN"
softhsm2-util --show-slots
pkcs11-tool --module "$AEGIS_PKCS11_MODULE" --list-slots
```

## Map to `Pkcs11CustodyOps` / `HsmCustodyProvider`

When linking a PKCS#11 crate, implement [`HsmCustodyProvider`](../../crates/aegis-topology/src/custody.rs) + [`Pkcs11CustodyOps`](../../crates/aegis-topology/src/custody.rs):

| AEGIS method | PKCS#11 | SoftHSM pilot note |
|--------------|---------|-------------------|
| `list_slots` | `C_GetSlotList` | `softhsm2-util --show-slots` |
| `generate_wrap_seed_share` | `C_GenerateKeyPair` + wrap | Ed25519 in-token; export wrapped Shamir share only |
| `sign_admission` | `C_Sign` | No seed export |
| `verify_wrapped_share` | unwrap + metadata | Bind authority index / Shamir x in AAD |

Until wired, `select_ceremony_custody(CeremonyCustodyMode::Hardware)` returns
`CeremonyError::HsmUnavailable` with [`hsm_unavailable_hint`](../../crates/aegis-topology/src/custody.rs).

Suggested integration env (future Rust build):

```bash
export AEGIS_PKCS11_MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
export AEGIS_PKCS11_SLOT=0
export AEGIS_PKCS11_PIN=...
```

## Smoke notes (operator host)

Run on a WSL/Linux host **with** SoftHSM installed:

```bash
bash scripts/softhsm_init.sh
```

Capture `softhsm2-util --show-slots` output in your ops log. Expected:

- Token label `aegis-ceremony` (or your `AEGIS_SOFTHSM_TOKEN_LABEL`)
- `pkcs11-tool --list-slots` lists the same slot when `opensc` is installed

**This repo does not commit host-specific slot dumps.** If SoftHSM is absent (typical
Windows CI), the init script is a no-op with install instructions — that is intentional.

## Ceremony workflow (unchanged logic)

1. **Pilot / lab:** `SoftwareCustodyProvider` or `SimulatedHsmProvider` + `aegis-ceremony`
2. **Next step:** implement `HsmCustodyProvider` against SoftHSM module; run ceremony with
   `--custody hardware` once the Rust PKCS#11 link exists
3. **Production:** swap module path to vendor HSM; same `Pkcs11CustodyOps` contract

See [`consortium_key_ceremony.md`](consortium_key_ceremony.md) for M-of-N steps, Shamir
shares, and roster TOML.

## Residual (honest)

- SoftHSM is a **software token**, not a tamper-resistant HSM.
- No in-tree PKCS#11 dependency yet — pilot is ops + contract only.
- MPC / proactive refresh remain **External**.
