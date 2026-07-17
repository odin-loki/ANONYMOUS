# Constant-time evidence CI / local `dudect`

**Status (2026-07-17):** Cargo timing smokes in-tree; full `dudect` is **WSL/Linux ops** (not Windows-native).

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

## Full `dudect` under WSL (Ubuntu)

Pin frequency and isolate a core when possible:

```bash
# Inside WSL2 Ubuntu
sudo apt update && sudo apt install -y build-essential git clang

# Example: dudect-style harness against a small C/Rust FFI stub, or use
# https://github.com/oreparaz/dudect (C) / rust ports.
#
# Recommended workflow for AEGIS primitives:
# 1. Build a tiny staticlib that exports:
#      uint8_t aegis_ct_contains(const uint8_t tag[32]);
#      uint8_t aegis_verify_mac(...);
# 2. Drive class-0 (miss / bad MAC) vs class-1 (hit / good MAC) inputs.
# 3. Run until dudect reports "nteager" / t-statistic below threshold.

# CPU isolation sketch (bare metal / privileged VM; WSL2 may ignore):
# echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
# taskset -c 2 ./dudect_replay_contains
```

### Suggested class split

| Primitive | Class 0 | Class 1 |
|-----------|---------|---------|
| `ReplayCache::contains_ct` | tag **absent** from FIFO | tag **present** |
| Sphinx `verify_mac` | last-byte flipped packet | valid packet |

Keep cache capacity fixed across trials (same as production scan bound). Do not insert during the timed probe — use `contains_ct` only.

### CI note

Windows runners: rely on `timing_smoke` + `dudect_smoke`.  
Linux CI (optional job): install dudect harness + run ≥10⁵ traces with pinned core.

See also `docs/AEGIS_crypto_constant_time_review.md`.
