# Constant-time evidence CI / local `dudect`

**Status (2026-07-18):** In-tree timing smokes; WSL wrappers capture smoke + lab attempt evidence;
`tools/dudect/` auto-clones oreparaz/dudect + `aegis-crypto-dudect-ffi` Rust exports scaffold the
external lab boundary. Full statistical runs on an **isolated CPU** remain **External**.

## In-tree smokes (run anywhere)

```bash
cd crates
cargo test -p aegis-crypto --test timing_smoke --test dudect_smoke
```

| Harness | What it checks |
|---------|----------------|
| `tests/timing_smoke.rs` | Sphinx `verify_mac` good vs bad median ratio &lt; 3× |
| `tests/dudect_smoke.rs` | `ReplayCache::contains_ct` hit vs miss: median ratio &lt; 2.5× and rank `P(hit>miss)` in `[0.20, 0.80]` |

These catch **gross** early-exit skew only. They are **not** cryptographic timing proofs.

## WSL smoke + evidence capture (Windows host)

WSL2 runs Linux-native smokes from a Windows checkout. This is **not** sufficient isolation
for rigorous `dudect` evidence (hypervisor jitter, shared cores) — use bare-metal or a
dedicated lab VM with CPU pinning for ≥10⁵ traces.

**PowerShell (repo root):**

```powershell
.\scripts\run_dudect_wsl.ps1
```

**Direct WSL:**

```bash
wsl -e bash -lc '/mnt/c/path/to/ANONYMOUS/scripts/run_dudect_wsl.sh'
```

The script:

1. Runs `timing_smoke` + `dudect_smoke` under WSL (`cargo test -p aegis-crypto …`).
2. Writes timestamped output to [`sim/dudect_wsl_smoke.txt`](../../sim/dudect_wsl_smoke.txt) (gitignored artifact; copy into `docs/ops/evidence/` for release records if desired).

**Full lab attempt (FFI + Makefile + short dudect stats):**

```powershell
wsl -e bash -lc '/mnt/c/path/to/ANONYMOUS/scripts/run_dudect_lab_wsl.sh'
# or: DUDECT_MEASUREMENTS=5000 wsl -e bash -lc '.../run_dudect_lab_wsl.sh'
```

Captures best-effort build/run output to [`sim/dudect_lab_attempt.txt`](../../sim/dudect_lab_attempt.txt).
WSL2 is **not** sufficient for ≥10⁵ isolated traces — see blockers at end of that file.

**Prerequisites in WSL:** `curl https://sh.rustup.rs -sSf | sh` (or distro package), then `rustup default stable`.

## External lab: `tools/dudect/` + `aegis-crypto-dudect-ffi` (Linux)

Scaffolding lives in-tree; statistical runs are operator-owned.

### Rust FFI exports (`aegis-crypto-dudect-ffi`)

Separate crate (not required for default smokes). Exports:

| Symbol | Class 0 | Class 1 |
|--------|---------|---------|
| `aegis_ct_contains(class_bit)` | miss (`class_bit == 0`) | hit (`class_bit != 0`) |
| `aegis_ct_verify_mac(class_bit)` | bad MAC (gamma byte flipped) | valid packet |

Init once before timing loops:

- `aegis_dudect_replay_lab_init(AEGIS_DUDECT_REPLAY_CAPACITY)` — fills FIFO (default 64)
- `aegis_dudect_mac_lab_init()` — deterministic Sphinx fixtures

Build staticlib (Linux lab / `tools/dudect/Makefile`; optional on Windows):

```bash
cd crates
cargo build --manifest-path aegis-crypto-dudect-ffi/Cargo.toml --release \
  --target-dir target/dudect-ffi
# → target/dudect-ffi/release/libaegis_crypto_dudect_ffi.a
```

Optional FFI unit checks:

```bash
cargo test --manifest-path aegis-crypto-dudect-ffi/Cargo.toml
```

### C harness skeleton (Linux)

```bash
cd tools/dudect
make                    # stub binaries: FFI smoke only, no dudect stats
make lab                # auto-clone oreparaz/dudect into ../dudect-upstream + run harnesses
DUDECT_MEASUREMENTS=5000 make lab   # short lab attempt (not release evidence)
# Pin core on bare metal / privileged VM:
taskset -c 2 ./harness_replay_contains
taskset -c 2 ./harness_verify_mac
```

The Makefile clones [oreparaz/dudect](https://github.com/oreparaz/dudect) when `../dudect-upstream/src/dudect.h`
is missing (upstream is header-only; no separate `dudect.c`). Override with `DUDECT_DIR=/path/to/dudect`.

Stub targets print sanity output and exit; they do **not** claim CT. With dudect linked,
harnesses use `AEGIS_DUDECT_MEASUREMENTS` (default **100000** — tune upward for release evidence).

### Suggested class split

| Primitive | Class 0 | Class 1 |
|-----------|---------|---------|
| `ReplayCache::contains_ct` | tag **absent** from FIFO | tag **present** |
| Sphinx `verify_mac` | gamma byte flipped | valid packet |

Keep cache capacity fixed across trials (same as production scan bound). Do not insert during the timed probe — use `contains_ct` / `aegis_ct_contains` only.

### CPU isolation sketch (bare metal / privileged VM)

```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
taskset -c 2 ./harness_replay_contains
```

WSL2 may ignore cpufreq and isolation; treat WSL smokes as CI guards only.

### Honest External gap

In-tree wiring: FFI + C harnesses + Makefile (auto-clone dudect) + WSL lab script +
[`sim/dudect_lab_attempt.txt`](../../sim/dudect_lab_attempt.txt) best-effort capture.

**Still External (not automated in CI):** running ≥10⁵ traces **per primitive** on an isolated
core (bare metal / privileged VM with cpufreq + `taskset`), archiving t-statistic reports, and
sign-off for release claims. WSL2 lab runs document wiring only.

### CI note

Windows runners: `timing_smoke` + `dudect_smoke` only (no Makefile).  
Linux CI (`.github/workflows/ci.yml`): `cargo test --workspace`, Unix kem seed mode tests,
and `sim/` pytest with `PYTHONPATH=.`. Optional self-hosted WSL agent may run `run_dudect_lab_wsl.sh`.
Optional manual dudect job on pinned hardware for release evidence.

See also `docs/AEGIS_crypto_constant_time_review.md`.
