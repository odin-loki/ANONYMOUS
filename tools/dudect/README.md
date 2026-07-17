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
requires ≥10⁵ traces on an isolated CPU — see [`docs/ops/constant_time_ci.md`](../../docs/ops/constant_time_ci.md).

**Windows:** use in-tree `cargo test -p aegis-crypto --test timing_smoke --test dudect_smoke`;
do not expect this Makefile to run natively.
