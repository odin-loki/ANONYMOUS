# tools/dudect

In-repo **boundary** for external [oreparaz/dudect](https://github.com/oreparaz/dudect) timing
experiments against AEGIS constant-time probes.

| Artifact | Role |
|----------|------|
| `aegis_dudect.h` | C declarations for `aegis-crypto-dudect-ffi` exports |
| `harness_replay_contains.c` | Class-0 miss vs class-1 hit on `ReplayCache::contains_ct` |
| `harness_verify_mac.c` | Class-0 bad MAC vs class-1 valid Sphinx `verify_mac` |
| `Makefile` | Linux-only: build staticlib + stub or full dudect binaries |

**Not a proof:** stub targets only sanity-check FFI wiring. Statistical CT evidence
requires ≥10⁵ traces on an **isolated** CPU — see [`docs/ops/constant_time_ci.md`](../../docs/ops/constant_time_ci.md).

## Quick start (Linux / WSL)

```bash
cd tools/dudect
make                    # stub FFI smoke only
make lab                # auto-clone dudect + harnesses + run (default timeout 180s/harness)
make lab-deepen         # ~10–12 min deepen (replay 600s/1e5, mac 180s/1e4 chunks)
DUDECT_MEASUREMENTS=5000 DUDECT_MAX_CHUNKS=20 make lab   # short attempt
```

Harnesses print `AEGIS_DUDECT_SUMMARY` with `evidence_code` in
`{LEAKAGE_FOUND, BUDGET_EXHAUSTED}` (timeout emits `TIMEOUT` via Makefile).

| Tunable | Meaning |
|---------|---------|
| `DUDECT_MEASUREMENTS` | Chunk size per `dudect_main` (default `100000`) |
| `DUDECT_MAX_CHUNKS` | Stop after N chunks; `0` = until leakage |
| `DUDECT_TIMEOUT_REPLAY` / `DUDECT_TIMEOUT_MAC` | Per-harness wall-clock seconds |

The Makefile clones `oreparaz/dudect` into `../dudect-upstream` when missing (`make dudect-upstream`).
Override location: `make DUDECT_DIR=/path/to/dudect lab`.

**Windows host:** use in-tree `cargo test -p aegis-crypto --test timing_smoke --test dudect_smoke`,
or `.\scripts\run_dudect_lab_wsl.ps1 -LabMode deepen` under WSL2.
Do not expect this Makefile to run natively on Windows.

## Release evidence (External operator)

On bare metal or a privileged VM with CPU pinning:

```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
taskset -c 2 ./harness_replay_contains
taskset -c 2 ./harness_verify_mac
```

WSL2 lacks reliable cpufreq/taskset isolation — treat WSL runs as wiring / deepen smoke only.
Never equate high WSL trace counts with the External ≥10⁵ **isolated** bar.
