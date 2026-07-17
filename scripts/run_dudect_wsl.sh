#!/usr/bin/env bash
# Run in-tree constant-time smokes under WSL/Linux and capture evidence.
# Full oreparaz/dudect harness is External — see docs/ops/constant_time_ci.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/crates"

EVIDENCE_DIR="$ROOT/sim"
EVIDENCE_FILE="$EVIDENCE_DIR/dudect_wsl_smoke.txt"
mkdir -p "$EVIDENCE_DIR"

{
  echo "=== AEGIS WSL constant-time smoke ==="
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -a)"
  echo "rustc: $(rustc --version 2>/dev/null || echo 'missing')"
  echo "cargo: $(cargo --version 2>/dev/null || echo 'missing')"
  echo
  echo "--- in-tree timing_smoke + dudect_smoke ---"
} >"$EVIDENCE_FILE"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo not found in WSL. Install Rust: https://rustup.rs" | tee -a "$EVIDENCE_FILE"
  exit 1
fi

set +e
cargo test -p aegis-crypto --test timing_smoke --test dudect_smoke -- --nocapture 2>&1 | tee -a "$EVIDENCE_FILE"
TEST_EXIT=${PIPESTATUS[0]}
set -e

{
  echo
  echo "--- external gap (not run by this script) ---"
  echo "Full oreparaz/dudect C harness with isolated CPU, >=1e5 traces, and"
  echo "class-0/class-1 probes for verify_mac / contains_ct requires a dedicated"
  echo "Linux lab (bare metal or VM with cpufreq/taskset). WSL2 may ignore isolation."
  echo "See docs/ops/constant_time_ci.md for manual dudect-bench workflow."
  echo
  echo "exit_code: $TEST_EXIT"
} >>"$EVIDENCE_FILE"

echo "Evidence written to $EVIDENCE_FILE"
exit "$TEST_EXIT"
