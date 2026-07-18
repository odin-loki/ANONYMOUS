#!/usr/bin/env bash
# WSL/Linux: seed Sphinx fuzz corpus, run cargo-fuzz, write honest evidence.
# Wave A6 / S1 deepen. Not a formal proof. No Docker.
#
# Env:
#   SPHINX_FUZZ_MODE     short | overnight | custom   (default: short)
#   SPHINX_FUZZ_SECONDS  wall seconds for -max_total_time (overrides mode default)
#   SPHINX_FUZZ_TARGET   cargo-fuzz binary (default: fuzz_sphinx_process)
#   SPHINX_FUZZ_RSS_MB   libFuzzer rss limit (default: 4096)
#   SPHINX_FUZZ_TIMEOUT  per-input timeout seconds (default: 5)
#   SPHINX_FUZZ_SKIP_SEED 1 = skip corpus seed step
#   SPHINX_FUZZ_ALLOW_SMOKE 1 = if cargo-fuzz unavailable, fall back to cargo test smoke
#
# short     → ~720s (agent-friendly 10–15 min cap)
# overnight → 28800s (8h recipe)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT/crates/aegis-crypto/fuzz"
EVIDENCE="$ROOT/sim/sphinx_fuzz_evidence.txt"
RAW_LOG="$ROOT/sim/sphinx_fuzz_raw.log"
TARGET="${SPHINX_FUZZ_TARGET:-fuzz_sphinx_process}"
RSS_MB="${SPHINX_FUZZ_RSS_MB:-4096}"
INPUT_TO="${SPHINX_FUZZ_TIMEOUT:-5}"
MODE="${SPHINX_FUZZ_MODE:-short}"
SKIP_SEED="${SPHINX_FUZZ_SKIP_SEED:-0}"
ALLOW_SMOKE="${SPHINX_FUZZ_ALLOW_SMOKE:-1}"

case "$MODE" in
  short) DEFAULT_SECS=720 ;;
  overnight) DEFAULT_SECS=28800 ;;
  custom) DEFAULT_SECS="${SPHINX_FUZZ_SECONDS:-720}" ;;
  *)
    echo "unknown SPHINX_FUZZ_MODE=$MODE (use short|overnight|custom)" >&2
    exit 2
    ;;
esac
SECS="${SPHINX_FUZZ_SECONDS:-$DEFAULT_SECS}"

mkdir -p "$ROOT/sim" "$FUZZ_DIR/artifacts/$TARGET"

have_cmd() { command -v "$1" >/dev/null 2>&1; }

git_tip() {
  git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown"
}

write_header() {
  cat >"$EVIDENCE" <<EOF
# AEGIS Sphinx cargo-fuzz evidence (wave A6 / S1)
# Captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Host: $(uname -a)
# Repo tip: $(git_tip)
# Mode: $MODE
# Target: $TARGET
# Requested max_total_time_s: $SECS
#
# HONEST SCOPE: crash/panic search only. Not a mechanized proof.
# Not claimed: EasyCrypt, bit-exact Sphinx verification, anonymity sims.

## Environment
EOF
  {
    echo "rustc_stable: $(rustc --version 2>/dev/null || echo missing)"
    echo "rustc_nightly: $(rustc +nightly --version 2>/dev/null || echo missing)"
    echo "cargo: $(cargo --version 2>/dev/null || echo missing)"
    echo "cargo_fuzz: $(cargo fuzz --version 2>/dev/null || echo missing)"
    echo "nproc: $(nproc 2>/dev/null || echo unknown)"
    echo "fuzz_dir: $FUZZ_DIR"
    echo
  } >>"$EVIDENCE"
}

append() { printf '%s\n' "$@" >>"$EVIDENCE"; }

count_artifacts() {
  local dir="$FUZZ_DIR/artifacts/$TARGET"
  if [ ! -d "$dir" ]; then
    echo 0
    return
  fi
  # Count crash/oom/timeout artifacts only (ignore dirs / readme-like noise).
  find "$dir" -maxdepth 1 -type f \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' -o -name 'leak-*' \) 2>/dev/null | wc -l | tr -d ' '
}

list_artifacts() {
  local dir="$FUZZ_DIR/artifacts/$TARGET"
  [ -d "$dir" ] || return 0
  find "$dir" -maxdepth 1 -type f \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' -o -name 'leak-*' \) 2>/dev/null | sort || true
}

parse_stats() {
  # Best-effort parse of libFuzzer DONE / summary lines from raw log.
  local log="$1"
  local execs="unknown"
  local cov="unknown"
  local corp="unknown"
  local exec_s="unknown"
  local done_line=""
  if [ -f "$log" ]; then
    done_line="$(grep -E 'DONE|done_' "$log" | tail -n 1 || true)"
    if [ -n "$done_line" ]; then
      # Prefer "#N DONE ..." form; else last DONE line.
      if [[ "$done_line" =~ ^#([0-9]+) ]]; then
        execs="${BASH_REMATCH[1]}"
      fi
      if [[ "$done_line" =~ cov:\ ([0-9]+) ]]; then cov="${BASH_REMATCH[1]}"; fi
      if [[ "$done_line" =~ corp:\ ([0-9]+/[0-9]+) ]]; then corp="${BASH_REMATCH[1]}"; fi
      if [[ "$done_line" =~ exec/s:\ ([0-9]+) ]]; then exec_s="${BASH_REMATCH[1]}"; fi
    fi
    # Fallback: last progress line with leading #count
    if [ "$execs" = "unknown" ]; then
      local prog
      prog="$(grep -E '^#[0-9]+' "$log" | tail -n 1 || true)"
      if [[ "$prog" =~ ^#([0-9]+) ]]; then
        execs="${BASH_REMATCH[1]}"
      fi
      if [ "$cov" = "unknown" ] && [[ "$prog" =~ cov:\ ([0-9]+) ]]; then cov="${BASH_REMATCH[1]}"; fi
      if [ "$corp" = "unknown" ] && [[ "$prog" =~ corp:\ ([0-9]+/[0-9]+) ]]; then corp="${BASH_REMATCH[1]}"; fi
      if [ "$exec_s" = "unknown" ] && [[ "$prog" =~ exec/s:\ ([0-9]+) ]]; then exec_s="${BASH_REMATCH[1]}"; fi
    fi
  fi
  append "## Fuzz stats (parsed from libFuzzer log)"
  append "execs_approx: $execs"
  append "cov: $cov"
  append "corp: $corp"
  append "exec_per_s: $exec_s"
  append "done_line: ${done_line:-"(none)"}"
  append ""
}

run_seed() {
  append "## Corpus seed"
  if [ "$SKIP_SEED" = "1" ]; then
    append "skipped: SPHINX_FUZZ_SKIP_SEED=1"
    append ""
    return 0
  fi
  local seed_out
  if have_cmd python3; then
    seed_out="$(python3 "$ROOT/scripts/seed_sphinx_fuzz_corpus.py" 2>&1)" || {
      append "seed_status: FAILED"
      append "$seed_out"
      append ""
      return 1
    }
  elif have_cmd python; then
    seed_out="$(python "$ROOT/scripts/seed_sphinx_fuzz_corpus.py" 2>&1)" || {
      append "seed_status: FAILED"
      append "$seed_out"
      append ""
      return 1
    }
  else
    append "seed_status: FAILED (no python3/python)"
    append ""
    return 1
  fi
  append "seed_status: OK"
  append "$(echo "$seed_out" | tail -n 5)"
  local n
  n="$(find "$FUZZ_DIR/corpus/$TARGET" -type f 2>/dev/null | wc -l | tr -d ' ')"
  append "corpus_files: $n"
  append ""
}

run_cargo_fuzz() {
  append "## cargo-fuzz run"
  append "command: cargo +nightly fuzz run $TARGET -- -max_total_time=$SECS -rss_limit_mb=$RSS_MB -timeout=$INPUT_TO -artifact_prefix=artifacts/$TARGET/"
  append "started_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  append ""

  local start_ts end_ts rc
  start_ts="$(date +%s)"
  set +e
  (
    cd "$FUZZ_DIR"
    # libFuzzer prints to stderr; capture both.
    cargo +nightly fuzz run "$TARGET" -- \
      -max_total_time="$SECS" \
      -rss_limit_mb="$RSS_MB" \
      -timeout="$INPUT_TO" \
      -artifact_prefix="artifacts/$TARGET/"
  ) >"$RAW_LOG" 2>&1
  rc=$?
  set -e
  end_ts="$(date +%s)"
  local wall=$((end_ts - start_ts))

  append "finished_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  append "wall_clock_s: $wall"
  append "cargo_fuzz_exit: $rc"
  append "raw_log: sim/sphinx_fuzz_raw.log"
  append ""

  parse_stats "$RAW_LOG"

  local crashes
  crashes="$(count_artifacts)"
  append "## Artifacts"
  append "crash_oom_timeout_count: $crashes"
  if [ "$crashes" != "0" ]; then
    append "findings:"
    local f
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      append "  - ${f#"$ROOT"/}"
    done < <(list_artifacts)
  else
    append "findings: none in artifacts/$TARGET/"
  fi
  append ""

  append "## Verdict"
  if [ "$rc" -eq 0 ] && [ "$crashes" = "0" ]; then
    append "RESULT_CODE=NO_CRASH"
    append "summary: Timed libFuzzer run completed with exit 0 and zero crash/oom/timeout artifacts."
  elif [ "$crashes" != "0" ]; then
    append "RESULT_CODE=FINDINGS"
    append "summary: Artifacts present under artifacts/$TARGET/ — triage with cargo +nightly fuzz tmin."
  else
    append "RESULT_CODE=RUN_ERROR"
    append "summary: cargo-fuzz exited $rc; see raw log. Not interpreted as a Sphinx proof either way."
  fi
  append ""
  append "## Not claimed"
  append "- Mechanized / EasyCrypt proof"
  append "- Exhaustive validity of Sphinx for all keys"
  append "- Security against adaptive network adversaries"
  append ""
  append "## 8h overnight recipe"
  append 'SPHINX_FUZZ_MODE=overnight bash scripts/run_sphinx_fuzz_evidence.sh'
  append '# or: cd crates/aegis-crypto/fuzz && cargo +nightly fuzz run fuzz_sphinx_process -- -max_total_time=28800 -rss_limit_mb=4096 -timeout=5 -artifact_prefix=artifacts/fuzz_sphinx_process/'
  append ""

  # Tail of raw log for quick inspection in the evidence file.
  append "## Raw log tail (last 40 lines)"
  if [ -f "$RAW_LOG" ]; then
    tail -n 40 "$RAW_LOG" | sed 's/^/  /' >>"$EVIDENCE"
  fi
  return "$rc"
}

run_smoke_fallback() {
  append "## Fallback: cargo test smoke (cargo-fuzz unavailable)"
  append "reason: nightly and/or cargo-fuzz missing on this host"
  append "command: cargo test -p aegis-crypto --test vectors"
  append "started_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local rc
  set +e
  (cd "$ROOT" && cargo test -p aegis-crypto --test vectors) >"$RAW_LOG" 2>&1
  rc=$?
  set -e
  append "finished_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  append "cargo_test_exit: $rc"
  append ""
  append "## Verdict"
  if [ "$rc" -eq 0 ]; then
    append "RESULT_CODE=SMOKE_ONLY"
    append "summary: Fuzz binary not run; vectors smoke passed. Install nightly + cargo-fuzz for real evidence."
  else
    append "RESULT_CODE=SMOKE_FAILED"
    append "summary: Fallback cargo test failed; see sim/sphinx_fuzz_raw.log"
  fi
  append ""
  append "## Install (WSL/Linux, no Docker)"
  append "rustup toolchain install nightly"
  append "cargo install cargo-fuzz"
  append "SPHINX_FUZZ_MODE=short bash scripts/run_sphinx_fuzz_evidence.sh"
  append ""
  append "## Raw log tail (last 40 lines)"
  tail -n 40 "$RAW_LOG" | sed 's/^/  /' >>"$EVIDENCE" || true
  return "$rc"
}

main() {
  write_header
  run_seed || true

  if have_cmd cargo && rustc +nightly --version >/dev/null 2>&1 && cargo fuzz --version >/dev/null 2>&1; then
    set +e
    run_cargo_fuzz
    local rc=$?
    set -e
    echo "Evidence written: $EVIDENCE"
    exit "$rc"
  fi

  append "cargo_fuzz_available: no"
  if [ "$ALLOW_SMOKE" = "1" ]; then
    set +e
    run_smoke_fallback
    local rc=$?
    set -e
    echo "Evidence written (smoke fallback): $EVIDENCE"
    exit "$rc"
  fi

  append "## Verdict"
  append "RESULT_CODE=TOOLING_MISSING"
  append "summary: nightly/cargo-fuzz missing; SPHINX_FUZZ_ALLOW_SMOKE=0 so no fallback."
  echo "Evidence written: $EVIDENCE"
  exit 3
}

main "$@"
