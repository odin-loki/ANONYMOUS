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
make lab                # auto-clone dudect + build full harnesses + run (default 1e5 measurements)
DUDECT_MEASUREMENTS=5000 make lab   # short statistical attempt (lab only; not release evidence)
```

The Makefile clones `oreparaz/dudect` into `../dudect-upstream` when missing (`make dudect-upstream`).
Override location: `make DUDECT_DIR=/path/to/dudect lab`.

**Windows host:** use in-tree `cargo test -p aegis-crypto --test timing_smoke --test dudect_smoke`,
or `.\scripts\run_dudect_wsl.ps1` / `scripts/run_dudect_lab_wsl.sh` under WSL2.
Do not expect this Makefile to run natively on Windows.

## Release evidence (External operator)

On bare metal or a privileged VM with CPU pinning:

```bash
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
taskset -c 2 ./harness_replay_contains
taskset -c 2 ./harness_verify_mac
```

WSL2 lacks reliable cpufreq/taskset isolation — treat WSL runs as wiring smoke only.
