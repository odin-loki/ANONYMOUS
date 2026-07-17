# Constant-time evidence CI / local `dudect`

**Status (2026-07-17):** In-tree timing smokes; WSL wrapper captures smoke evidence; in-repo
`tools/dudect/` + `dudect-ffi` Rust exports scaffold the external lab boundary. Full
oreparaz/dudect statistical runs remain **External** (operator + isolated CPU).

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
# Full dudect (External operator step):
git clone https://github.com/oreparaz/dudect.git ../dudect-upstream
make DUDECT_DIR=../dudect-upstream
# Pin core on bare metal / privileged VM:
taskset -c 2 ./harness_replay_contains
taskset -c 2 ./harness_verify_mac
```

Stub targets print sanity output and exit; they do **not** claim CT. With `DUDECT_DIR`,
harnesses aim for ≥10⁵ measurements (`number_measurements = 100000` in skeleton — tune upward
for release evidence).

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

In-tree wiring stops at FFI + C skeleton + Makefile. **Not automated:** cloning oreparaz/dudect,
adapting harnesses to upstream API drift, running ≥10⁵ traces per primitive on an isolated core,
and archiving t-statistic reports. That is B-class External per [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md).

### CI note

Windows runners: `timing_smoke` + `dudect_smoke`, or optional `run_dudect_wsl.ps1` on self-hosted WSL agents.  
Linux CI (optional job): `tools/dudect` stub build + optional manual dudect job on pinned hardware.

See also `docs/AEGIS_crypto_constant_time_review.md`.
