#!/usr/bin/env bash
# Append a line-buffered verify_mac deepen capture to existing lab evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EV="$ROOT/sim/dudect_lab_attempt.txt"
SUM="$ROOT/sim/dudect_lab_summary.txt"
DUDECT_DIR="$ROOT/tools/dudect"
MEAS="${DUDECT_MEASUREMENTS:-10000}"
MAX_CHUNKS="${DUDECT_MAX_CHUNKS:-200}"
TO_MAC="${DUDECT_TIMEOUT_MAC:-180}"

cd "$DUDECT_DIR"
make harness_verify_mac DUDECT_MEASUREMENTS="$MEAS" DUDECT_MAX_CHUNKS="$MAX_CHUNKS"

{
  echo
  echo "=== C6 MAC re-capture (line-buffered; after deepen replay TIMEOUT) ==="
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "DUDECT_MEASUREMENTS: $MEAS"
  echo "DUDECT_MAX_CHUNKS: $MAX_CHUNKS"
  echo "DUDECT_TIMEOUT_MAC: $TO_MAC"
} | tee -a "$EV"

set +e
if command -v stdbuf >/dev/null 2>&1; then
  timeout --signal=TERM --kill-after=10 "$TO_MAC" stdbuf -oL -eL ./harness_verify_mac 2>&1 | tee -a "$EV"
  ec=${PIPESTATUS[0]}
else
  timeout --signal=TERM --kill-after=10 "$TO_MAC" ./harness_verify_mac 2>&1 | tee -a "$EV"
  ec=${PIPESTATUS[0]}
fi
set -e

case $ec in
  0) hint=LEAKAGE_FOUND ;;
  2) hint=BUDGET_EXHAUSTED ;;
  124)
    hint=TIMEOUT
    echo "AEGIS_DUDECT_SUMMARY primitive=Sphinx::verify_mac evidence_code=TIMEOUT isolation=none platform=linux_or_wsl external_bar=isolated_ge_1e5_per_primitive" | tee -a "$EV"
    ;;
  *) hint=ERROR ;;
esac
echo "harness_exit: harness_verify_mac=$ec evidence_hint=$hint" | tee -a "$EV"

REPLAY_LAST=$(awk '
  /AEGIS dudect: ReplayCache::contains_ct/ { in_sec=1; last=""; next }
  in_sec && /^--- run harness_verify_mac/ { in_sec=0 }
  in_sec && /^harness_exit: harness_replay/ { in_sec=0 }
  in_sec && /^meas:/ { last=$0 }
  END { print last }
' "$EV")

MAC_LAST=$(awk '
  /AEGIS dudect: Sphinx verify_mac/ { in_sec=1; last=""; next }
  in_sec && /^meas:/ { last=$0 }
  END { print last }
' "$EV")

parse() {
  printf '%s\n' "$1" | sed -n 's/.*meas:[[:space:]]*\([0-9.]*\)[[:space:]]*M,.*/\1/p' | \
    awk 'NF{printf "%.0f", $1 * 1e6; exit}'
}
RT=$(parse "$REPLAY_LAST")
MT=$(parse "$MAC_LAST")
RT=${RT:-0}
MT=${MT:-0}

{
  echo "=== AEGIS dudect lab summary ==="
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "lab_mode: deepen"
  echo "elapsed_sec_primary_deepen: 761"
  echo "chunk_measurements_replay: 100000"
  echo "chunk_measurements_mac_recapture: $MEAS"
  echo "timeout_replay_sec: 600"
  echo "timeout_mac_sec: $TO_MAC"
  echo "platform: WSL2_or_Linux"
  echo "isolation: none"
  echo "evidence_code_platform: WSL_NOT_ISOLATED"
  echo "external_bar: >=1e5 traces per primitive on isolated CPU (bare metal / privileged VM)"
  echo "external_bar_met: NO"
  echo "replay_contains_last_meas_line: $REPLAY_LAST"
  echo "verify_mac_last_meas_line: $MAC_LAST"
  echo "replay_contains_traces_approx: $RT"
  echo "verify_mac_traces_approx: $MT"
  echo "replay_evidence_code: TIMEOUT"
  echo "mac_harness_exit: $ec ($hint)"
  echo "honest_status: WSL deepen/wiring only; do NOT claim External isolated >=1e5"
  echo
  echo "--- summary / exit lines ---"
  grep -E '^AEGIS_DUDECT_SUMMARY|^harness_exit:' "$EV" | tail -20
  echo
  echo "full_log: $EV"
} | tee "$SUM"

echo "REPLAY_TRACES=$RT MAC_TRACES=$MT MAC_EC=$ec"
exit 0
