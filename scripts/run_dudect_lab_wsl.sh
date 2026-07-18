#!/usr/bin/env bash
# WSL/Linux: build aegis-crypto-dudect-ffi + tools/dudect harnesses and capture lab output.
# Full >=1e5 isolated dudect remains External — see docs/ops/constant_time_ci.md.
#
# Env tunables:
#   DUDECT_MEASUREMENTS / _REPLAY / _MAC   chunk sizes
#   DUDECT_MAX_CHUNKS / _REPLAY / _MAC     stop after N chunks; 0 = until leakage
#   DUDECT_TIMEOUT_REPLAY / _MAC / _SEC    per-harness / shared wall-clock seconds
#   DUDECT_LAB_MODE          short | deepen | custom (default short)
#   DUDECT_SKIP_SMOKE        1 = skip cargo timing/dudect smokes
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EVIDENCE_FILE="$ROOT/sim/dudect_lab_attempt.txt"
SUMMARY_FILE="$ROOT/sim/dudect_lab_summary.txt"
DUDECT_DIR="$ROOT/tools/dudect"
CRATES="$ROOT/crates"

LAB_MODE="${DUDECT_LAB_MODE:-short}"
case "$LAB_MODE" in
  short)
    MEAS_REPLAY="${DUDECT_MEASUREMENTS_REPLAY:-${DUDECT_MEASUREMENTS:-5000}}"
    MAX_CHUNKS_REPLAY="${DUDECT_MAX_CHUNKS_REPLAY:-${DUDECT_MAX_CHUNKS:-20}}"
    MEAS_MAC="${DUDECT_MEASUREMENTS_MAC:-${DUDECT_MEASUREMENTS:-5000}}"
    MAX_CHUNKS_MAC="${DUDECT_MAX_CHUNKS_MAC:-${DUDECT_MAX_CHUNKS:-20}}"
    TO_DEFAULT="${DUDECT_TIMEOUT_SEC:-60}"
    ;;
  deepen)
    # Large replay chunks (fewer log lines); smaller MAC chunks for flush-friendly deepen.
    MEAS_REPLAY="${DUDECT_MEASUREMENTS_REPLAY:-${DUDECT_MEASUREMENTS:-100000}}"
    MAX_CHUNKS_REPLAY="${DUDECT_MAX_CHUNKS_REPLAY:-${DUDECT_MAX_CHUNKS:-1200}}"
    MEAS_MAC="${DUDECT_MEASUREMENTS_MAC:-10000}"
    MAX_CHUNKS_MAC="${DUDECT_MAX_CHUNKS_MAC:-200}"
    TO_DEFAULT="${DUDECT_TIMEOUT_SEC:-600}"
    ;;
  custom|*)
    MEAS_REPLAY="${DUDECT_MEASUREMENTS_REPLAY:-${DUDECT_MEASUREMENTS:-100000}}"
    MAX_CHUNKS_REPLAY="${DUDECT_MAX_CHUNKS_REPLAY:-${DUDECT_MAX_CHUNKS:-0}}"
    MEAS_MAC="${DUDECT_MEASUREMENTS_MAC:-${DUDECT_MEASUREMENTS:-100000}}"
    MAX_CHUNKS_MAC="${DUDECT_MAX_CHUNKS_MAC:-${DUDECT_MAX_CHUNKS:-0}}"
    TO_DEFAULT="${DUDECT_TIMEOUT_SEC:-180}"
    ;;
esac

TO_REPLAY="${DUDECT_TIMEOUT_REPLAY:-$TO_DEFAULT}"
TO_MAC="${DUDECT_TIMEOUT_MAC:-${DUDECT_TIMEOUT_SEC:-$TO_DEFAULT}}"
if [ "$LAB_MODE" = "deepen" ] && [ -z "${DUDECT_TIMEOUT_MAC:-}" ] && [ -z "${DUDECT_TIMEOUT_SEC:-}" ]; then
  TO_MAC=180
fi
if [ "$LAB_MODE" = "deepen" ] && [ -z "${DUDECT_TIMEOUT_REPLAY:-}" ] && [ -z "${DUDECT_TIMEOUT_SEC:-}" ]; then
  TO_REPLAY=600
fi

SKIP_SMOKE="${DUDECT_SKIP_SMOKE:-0}"

mkdir -p "$ROOT/sim"

{
  echo "=== AEGIS dudect lab attempt (WSL/Linux) ==="
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(uname -a)"
  echo "rustc: $(rustc --version 2>/dev/null || echo 'missing')"
  echo "cargo: $(cargo --version 2>/dev/null || echo 'missing')"
  echo "cc: $(command -v gcc || command -v clang || echo 'missing')"
  echo "git: $(git --version 2>/dev/null || echo 'missing')"
  echo "nproc: $(nproc 2>/dev/null || echo unknown)"
  echo "LAB_MODE: $LAB_MODE"
  echo "DUDECT_MEASUREMENTS_REPLAY: $MEAS_REPLAY"
  echo "DUDECT_MAX_CHUNKS_REPLAY: $MAX_CHUNKS_REPLAY"
  echo "DUDECT_MEASUREMENTS_MAC: $MEAS_MAC"
  echo "DUDECT_MAX_CHUNKS_MAC: $MAX_CHUNKS_MAC"
  echo "DUDECT_TIMEOUT_REPLAY: $TO_REPLAY"
  echo "DUDECT_TIMEOUT_MAC: $TO_MAC"
  echo "DUDECT_SKIP_SMOKE: $SKIP_SMOKE"
  echo "evidence_codes: LEAKAGE_FOUND | BUDGET_EXHAUSTED | TIMEOUT | WSL_NOT_ISOLATED | EXTERNAL_BAR_UNMET"
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
STARTED_EPOCH=$(date +%s)

if [ "$SKIP_SMOKE" != "1" ]; then
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
else
  log "--- Step 1: skipped (DUDECT_SKIP_SMOKE=1) ---"
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
log "--- Step 3: tools/dudect Makefile lab (mode=$LAB_MODE) ---"
set +e
(
  cd "$DUDECT_DIR"
  # Force rebuild harnesses when chunk defines change (Make mtime alone is insufficient).
  rm -f harness_replay_contains harness_verify_mac
  make lab \
    DUDECT_MEASUREMENTS_REPLAY="$MEAS_REPLAY" \
    DUDECT_MAX_CHUNKS_REPLAY="$MAX_CHUNKS_REPLAY" \
    DUDECT_MEASUREMENTS_MAC="$MEAS_MAC" \
    DUDECT_MAX_CHUNKS_MAC="$MAX_CHUNKS_MAC" \
    DUDECT_TIMEOUT_REPLAY="$TO_REPLAY" \
    DUDECT_TIMEOUT_MAC="$TO_MAC"
) 2>&1 | tee -a "$EVIDENCE_FILE"
MAKE_EXIT=${PIPESTATUS[0]}
set -e
log "make lab exit_code: $MAKE_EXIT"
if [ "$MAKE_EXIT" -ne 0 ]; then
  LAB_EXIT=$MAKE_EXIT
fi

ENDED_EPOCH=$(date +%s)
ELAPSED=$((ENDED_EPOCH - STARTED_EPOCH))

# Parse last dudect meas lines per primitive section + summary footers.
extract_section_last_meas() {
  local start_pat="$1"
  local stop_pat="$2"
  awk -v start="$start_pat" -v stop="$stop_pat" '
    $0 ~ start { in_sec=1; last=""; next }
    in_sec && $0 ~ stop { in_sec=0 }
    in_sec && /^meas:/ { last=$0 }
    END { if (last != "") print last }
  ' "$EVIDENCE_FILE"
}

REPLAY_LAST=$(extract_section_last_meas "AEGIS dudect: ReplayCache::contains_ct" \
  "^(AEGIS dudect: Sphinx|--- run harness_verify_mac|harness_exit: harness_replay)" || true)
MAC_LAST=$(extract_section_last_meas "AEGIS dudect: Sphinx verify_mac" \
  "^(--- dudect lab complete|harness_exit: harness_verify_mac|make lab exit)" || true)
SUMMARIES=$(grep -E '^AEGIS_DUDECT_SUMMARY|^harness_exit:' "$EVIDENCE_FILE" || true)

# Best-effort numeric extract: "meas:   43.60 M" -> 43600000
parse_meas_count() {
  printf '%s\n' "$1" | sed -n 's/.*meas:[[:space:]]*\([0-9.]*\)[[:space:]]*M,.*/\1/p' | \
    awk 'NF{printf "%.0f", $1 * 1e6; exit}'
}

REPLAY_TRACES=$(parse_meas_count "$REPLAY_LAST")
MAC_TRACES=$(parse_meas_count "$MAC_LAST")
: "${REPLAY_TRACES:=0}"
: "${MAC_TRACES:=0}"

{
  echo "=== AEGIS dudect lab summary ==="
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "lab_mode: $LAB_MODE"
  echo "elapsed_sec: $ELAPSED"
  echo "chunk_measurements_replay: $MEAS_REPLAY"
  echo "max_chunks_replay: $MAX_CHUNKS_REPLAY"
  echo "chunk_measurements_mac: $MEAS_MAC"
  echo "max_chunks_mac: $MAX_CHUNKS_MAC"
  echo "timeout_replay_sec: $TO_REPLAY"
  echo "timeout_mac_sec: $TO_MAC"
  echo "platform: WSL2_or_Linux"
  echo "isolation: none"
  echo "evidence_code_platform: WSL_NOT_ISOLATED"
  echo "external_bar: >=1e5 traces per primitive on isolated CPU (bare metal / privileged VM)"
  echo "external_bar_met: NO"
  echo "replay_contains_last_meas_line: ${REPLAY_LAST%%$'\n'*}"
  echo "verify_mac_last_meas_line: ${MAC_LAST%%$'\n'*}"
  echo "replay_contains_traces_approx: $REPLAY_TRACES"
  echo "verify_mac_traces_approx: $MAC_TRACES"
  echo "honest_status: WSL deepen/wiring only; do NOT claim External isolated >=1e5"
  echo
  echo "--- summary / exit lines ---"
  echo "$SUMMARIES"
  echo
  echo "overall_exit_code: $LAB_EXIT"
  echo "full_log: $EVIDENCE_FILE"
} >"$SUMMARY_FILE"

{
  echo
  echo "--- External gap / blockers for >=1e5 isolated evidence ---"
  echo "1. CPU isolation: WSL2 hypervisor jitter; cpufreq/taskset often ineffective."
  echo "2. Upstream API: oreparaz/dudect is header-only (src/dudect.h); harnesses use DUDECT_IMPLEMENTATION."
  echo "3. Measurement budget: release evidence needs >=100000 traces per primitive on"
  echo "   a pinned bare-metal or privileged VM core (see tools/dudect/Makefile default)."
  echo "4. This run: LAB_MODE=$LAB_MODE"
  echo "   replay meas/chunks=${MEAS_REPLAY}/${MAX_CHUNKS_REPLAY}"
  echo "   mac meas/chunks=${MEAS_MAC}/${MAX_CHUNKS_MAC}"
  echo "   timeouts replay=${TO_REPLAY}s mac=${TO_MAC}s elapsed=${ELAPSED}s."
  echo "5. Approx traces observed (dudect printed meas, not isolated):"
  echo "   ReplayCache::contains_ct ~= $REPLAY_TRACES"
  echo "   Sphinx::verify_mac ~= $MAC_TRACES"
  echo "6. evidence_code_platform=WSL_NOT_ISOLATED; external_bar_met=NO"
  echo "7. Compact summary: $SUMMARY_FILE"
  echo
  echo "overall exit_code: $LAB_EXIT"
} >>"$EVIDENCE_FILE"

log "Evidence written to $EVIDENCE_FILE"
log "Summary written to $SUMMARY_FILE"
exit "$LAB_EXIT"
