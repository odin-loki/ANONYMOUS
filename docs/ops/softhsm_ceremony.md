# SoftHSM2 ceremony pilot (PKCS#11)

**Status:** **Succeeded** on OdinsPC WSL (2026-07-18) — SoftHSM2 user-local build +
token `aegis-ceremony` initialized; S6 ceremony regress green at tip `3819c1b`.
SoftHSM remains a **software token**, not hardware custody. **Not required for CI.**

**Parent:** [`consortium_key_ceremony.md`](consortium_key_ceremony.md)  
**APIs:** `Pkcs11CustodyOps`, `HsmCustodyProvider`, `SimulatedHsmProvider`, `select_ceremony_custody`  
**Evidence:** [`sim/softhsm_init_evidence.txt`](../../sim/softhsm_init_evidence.txt),
[`sim/softhsm_ceremony_regress.txt`](../../sim/softhsm_ceremony_regress.txt)

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

## Quick start (operator)

From repo root on WSL/Linux:

```bash
bash scripts/softhsm_probe.sh          # non-interactive; never hangs on sudo
bash scripts/softhsm_user_build.sh     # no sudo; builds into ~/.local if needed
bash scripts/softhsm_init.sh           # init token label aegis-ceremony
bash scripts/softhsm_init.sh --dry-run # probe only
bash scripts/softhsm_init.sh --evidence sim/softhsm_init_evidence.txt
```

From Windows PowerShell (path helper → WSL user `odin`):

```powershell
powershell -File scripts/softhsm_wsl.ps1 -Action probe
powershell -File scripts/softhsm_wsl.ps1 -Action user-build
powershell -File scripts/softhsm_wsl.ps1 -Action init -Evidence
powershell -File scripts/softhsm_wsl.ps1 -Action dry-run
powershell -File scripts/softhsm_wsl.ps1 -Action regress -Evidence   # ceremony regression
powershell -File scripts/softhsm_wsl.ps1 -Action verify              # probe+init+custody
```

### Ceremony regression harness (S6)

After a successful user-build + token init, re-verify without sudo:

```bash
bash scripts/softhsm_ceremony_regress.sh --evidence sim/softhsm_ceremony_regress.txt
```

Steps: probe → dry-run → init (expect `ALREADY_INITIALIZED`) → optional pkcs11-tool →
`cargo test -p aegis-topology custody::tests`. See
[`sim/softhsm_ceremony_regress.txt`](../../sim/softhsm_ceremony_regress.txt).

## Install paths

### Option A — system packages (requires sudo password)

```bash
sudo apt-get update
sudo apt-get install -y softhsm2 opensc
```

Common module path (set `AEGIS_PKCS11_MODULE` if different):

```text
/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
```

Non-interactive agents: probe with `sudo -n true` first. If it prints
`a password is required`, **do not** run bare `sudo` (it will hang). Use Option B.

### Option B — user-local build (no sudo) — **recommended when sudo needs a password**

`scripts/softhsm_user_build.sh` will:

1. Detect missing `uuid-dev` / `libtool`
2. `apt-get download` those debs + extract into `~/.local/aegis-build-deps` (no sudo)
3. Build SoftHSM2 2.6.1 into `~/.local`

```bash
bash scripts/softhsm_user_build.sh
# rebuild: AEGIS_SOFTHSM_FORCE_REBUILD=1 bash scripts/softhsm_user_build.sh
# dry-run: bash scripts/softhsm_user_build.sh --dry-run
```

| Artifact | Path |
|----------|------|
| `softhsm2-util` | `~/.local/bin/softhsm2-util` |
| PKCS#11 module | `~/.local/lib/softhsm/libsofthsm2.so` |
| `AEGIS_PKCS11_MODULE` | `$HOME/.local/lib/softhsm/libsofthsm2.so` |

Ensure `~/.local/bin` is on `PATH` (script does this for the session). Set
`LD_LIBRARY_PATH=$HOME/.local/lib` if a tool fails to load companion libs.

**Note:** Extracting the Ubuntu `softhsm2` `.deb` alone is **not** enough —
`softhsm2-util` hardcodes `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`. Prefer
Option B (configure `--prefix=$HOME/.local`) so the util and module match.

### Option C — optional `pkcs11-tool` without sudo

```bash
bash scripts/softhsm_fix_pkcs11_tool.sh
```

Token init does **not** require OpenSC; `softhsm2-util --show-slots` is sufficient.

## Init token (safe helper)

```bash
bash scripts/softhsm_init.sh
```

If `softhsm2-util` is missing, the script prints an unblock checklist and exits **0**
(so CI/agents without SoftHSM do not fail).

| Variable / flag | Default | Purpose |
|-----------------|---------|---------|
| `AEGIS_SOFTHSM_SLOT` | `0` | Token slot |
| `AEGIS_SOFTHSM_TOKEN_LABEL` | `aegis-ceremony` | Token label |
| `AEGIS_SOFTHSM_SO_PIN` / `AEGIS_SOFTHSM_USER_PIN` | `1234` | **Change in real ops** |
| `SOFTHSM2_CONF` | `~/.config/softhsm2/softhsm2.conf` | SoftHSM config |
| `AEGIS_PKCS11_MODULE` | `~/.local/...` if present else system path | PKCS#11 module |
| `--dry-run` | off | Probe only |
| `--evidence FILE` | unset | Append `RESULT_CODE=...` block |

Evidence `RESULT_CODE` values: `SUCCEEDED`, `ALREADY_INITIALIZED`, `MISSING_SOFTHSM`,
`SHOW_SLOTS_FAIL`, `INIT_FAIL`, `DRY_RUN`.

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
export AEGIS_PKCS11_MODULE=$HOME/.local/lib/softhsm/libsofthsm2.so
export AEGIS_PKCS11_SLOT=0   # note: SoftHSM may reassign slot id after init
export AEGIS_PKCS11_PIN=...
```

### Lab smoke (no SoftHSM required)

```bash
cd crates
cargo test -p aegis-topology custody::tests::simulated_hsm_lab_only_roundtrip
cargo test -p aegis-topology custody::tests::hsm_provider_fails_closed_on_this_host
```

One-liner after SoftHSM success (ops host):

```bash
export PATH="$HOME/.local/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.local/lib:${LD_LIBRARY_PATH:-}"
export AEGIS_PKCS11_MODULE="$HOME/.local/lib/softhsm/libsofthsm2.so"
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$HOME/.config/softhsm2/softhsm2.conf}"
softhsm2-util --show-slots | grep -A2 'aegis-ceremony'
# Rust PKCS#11 link still External — SimulatedHsmProvider remains the in-tree lab path.
```

## Host run: OdinsPC (2026-07-18, tip `ae536f1`) — **SUCCEEDED**

Evidence: [`sim/softhsm_init_evidence.txt`](../../sim/softhsm_init_evidence.txt)

| Step | Result |
|------|--------|
| `sudo -n true` | **Blocked** — password required (not used) |
| `apt-get download` uuid-dev/libtool + extract | **OK** (no sudo) |
| `scripts/softhsm_user_build.sh` → `~/.local` | **OK** — SoftHSM2 2.6.1 |
| `scripts/softhsm_init.sh` | **OK** — token `aegis-ceremony` initialized (slot reassigned by SoftHSM) |
| `pkcs11-tool --list-slots` | **OK** after `softhsm_fix_pkcs11_tool.sh` (libeac + opensc into `~/.local/lib`) |
| Hardware custody claim | **No** — software token only |

### Prior blocked runs (same host)

Earlier tips (`f531480`, `9ce640f`) documented sudo password + missing uuid-dev/libtool.
Those are superseded by the no-sudo user-build path above.

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
- Default SO/User PINs in the helper are lab defaults — change for any real ceremony.
