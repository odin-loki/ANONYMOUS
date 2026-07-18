#!/usr/bin/env bash
# WSL/Linux: build aegis-crypto-dudect-ffi + tools/dudect harnesses and capture lab output.
# Full >=1e5 isolated dudect remains External — see docs/ops/constant_time_ci.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_FILE="$ROOT/sim/dudect_lab_attempt.txt"
DUDECT_DIR="$ROOT/tools/dudect"
CRATES="$ROOT/crates"
SHORT_MEAS="${DUDECT_MEASUREMENTS:-5000}"

mkdir -p "$ROOT/sim"

{
  echo "=== AEGIS dudect lab attempt (WSL/Linux) ==="
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -a)"
  echo "rustc: $(rustc --version 2>/dev/null || echo 'missing')"
  echo "cargo: $(cargo --version 2>/dev/null || echo 'missing')"
  echo "cc: $(command -v gcc || command -v clang || echo 'missing')"
  echo "git: $(git --version 2>/dev/null || echo 'missing')"
  echo "DUDECT_MEASUREMENTS: $SHORT_MEAS"
  echo
} >"$EVIDENCE_FILE"

log() { echo "$@" | tee -a "$EVIDENCE_FILE"; }

if ! command -v cargo >/dev/null 2>&1; then
  log "BLOCKER: cargo not found in WSL. Install Rust: https://rustup.rs"
  exit 1
fi

if ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
  log "BLOCKER: no C compiler (gcc/clang). Install: sudo apt install build-essential"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  log "BLOCKER: git not found (needed to clone oreparaz/dudect)."
  exit 1
fi

LAB_EXIT=0

log "--- Step 1: in-tree timing_smoke + dudect_smoke ---"
set +e
(
  cd "$CRATES"
  cargo test -p aegis-crypto --test timing_smoke --test dudect_smoke -- --nocapture
) 2>&1 | tee -a "$EVIDENCE_FILE"
SMOKE_EXIT=${PIPESTATUS[0]}
set -e
log "smoke exit_code: $SMOKE_EXIT"
if [ "$SMOKE_EXIT" -ne 0 ]; then
  LAB_EXIT=$SMOKE_EXIT
fi

log
log "--- Step 2: build aegis-crypto-dudect-ffi staticlib ---"
set +e
(
  cd "$CRATES"
  CARGO_TARGET_DIR=target/dudect-ffi \
    cargo build --manifest-path aegis-crypto-dudect-ffi/Cargo.toml --release
) 2>&1 | tee -a "$EVIDENCE_FILE"
FFI_EXIT=${PIPESTATUS[0]}
set -e
log "ffi build exit_code: $FFI_EXIT"
if [ "$FFI_EXIT" -ne 0 ]; then
  LAB_EXIT=$FFI_EXIT
fi

log
log "--- Step 3: tools/dudect Makefile (auto-clone dudect + short lab) ---"
set +e
(
  cd "$DUDECT_DIR"
  DUDECT_MEASUREMENTS="$SHORT_MEAS" make lab
) 2>&1 | tee -a "$EVIDENCE_FILE"
MAKE_EXIT=${PIPESTATUS[0]}
set -e
log "make lab exit_code: $MAKE_EXIT"
if [ "$MAKE_EXIT" -ne 0 ]; then
  LAB_EXIT=$MAKE_EXIT
fi

{
  echo
  echo "--- External gap / blockers for >=1e5 isolated evidence ---"
  echo "1. CPU isolation: WSL2 hypervisor jitter; cpufreq/taskset often ineffective."
  echo "2. Upstream API: oreparaz/dudect is header-only (src/dudect.h); harnesses use DUDECT_IMPLEMENTATION."
  echo "3. Measurement budget: release evidence needs >=100000 traces per primitive on"
  echo "   a pinned bare-metal or privileged VM core (see tools/dudect/Makefile default)."
  echo "4. This script used DUDECT_MEASUREMENTS=$SHORT_MEAS for a best-effort lab run only."
  echo "5. Archive t-statistic reports from harness stdout on isolated hardware for release."
  echo
  echo "overall exit_code: $LAB_EXIT"
} >>"$EVIDENCE_FILE"

log "Evidence written to $EVIDENCE_FILE"
exit "$LAB_EXIT"
