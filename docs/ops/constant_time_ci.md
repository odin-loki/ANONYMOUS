# Constant-time evidence CI / local `dudect`

**Status (2026-07-17):** Cargo timing smokes in-tree; WSL wrapper runs smokes and captures evidence; full `dudect` C harness remains **External** (not Windows-native).

## In-tree smokes (run anywhere)

```bash
cd crates
cargo test -p aegis-crypto --test timing_smoke --test dudect_smoke
```

| Harness | What it checks |
|---------|----------------|
| `tests/timing_smoke.rs` | Sphinx `verify_mac` good vs bad median ratio &lt; 3× |
| `tests/dudect_smoke.rs` | `ReplayCache::contains_ct` hit vs miss: median ratio &lt; 2.5× and rank `P(hit>miss)` in `[0.20, 0.80]` |

These catch **gross** early-exit skew only. They are not a cryptographic timing proof.

## WSL smoke + evidence capture (Windows host)

WSL2 is the supported path for Linux-native timing runs from a Windows checkout.

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

## Full `dudect` under WSL/Linux (External lab)

Pin frequency and isolate a core when possible:

```bash
# Inside WSL2 Ubuntu (or bare-metal Linux lab)
sudo apt update && sudo apt install -y build-essential git clang

# Example: dudect-style harness against a small C/Rust FFI stub, or use
# https://github.com/oreparaz/dudect (C) / rust ports.
#
# Recommended workflow for AEGIS primitives:
# 1. Build a tiny staticlib that exports:
#      uint8_t aegis_ct_contains(const uint8_t tag[32]);
#      uint8_t aegis_verify_mac(...);
# 2. Drive class-0 (miss / bad MAC) vs class-1 (hit / good MAC) inputs.
# 3. Run until dudect reports no t-statistic leakage above threshold (≥10⁵ traces).

# CPU isolation sketch (bare metal / privileged VM; WSL2 may ignore):
# echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# taskset -c 2 ./dudect_replay_contains
```

**Honest External gap:** `run_dudect_wsl.sh` does **not** clone or run oreparaz/dudect. That requires a dedicated Linux lab, FFI stubs for each primitive, and operator time. The in-tree smokes + WSL evidence file are the scoped **Partial** mitigation; full dudect-bench is B-class External per [`RESEARCH_OPS_STATUS.md`](RESEARCH_OPS_STATUS.md).

### Suggested class split

| Primitive | Class 0 | Class 1 |
|-----------|---------|---------|
| `ReplayCache::contains_ct` | tag **absent** from FIFO | tag **present** |
| Sphinx `verify_mac` | last-byte flipped packet | valid packet |

Keep cache capacity fixed across trials (same as production scan bound). Do not insert during the timed probe — use `contains_ct` only.

### CI note

Windows runners: rely on `timing_smoke` + `dudect_smoke`, or optional `run_dudect_wsl.ps1` on self-hosted WSL agents.  
Linux CI (optional job): install dudect harness + run ≥10⁵ traces with pinned core.

See also `docs/AEGIS_crypto_constant_time_review.md`.
